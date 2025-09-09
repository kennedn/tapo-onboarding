# tapo_decrypt_view.py
# This script provides a custom mitmproxy content view and an addon for decrypting
# and displaying Tapo camera JSON data inline. It handles the handshake and decryption
# process for Tapo camera communication.

import os
import json
import base64
import hashlib
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

from mitmproxy import http, ctx, contentviews
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

USER_AGENT = "Tapo CameraClient Android"

@dataclass
class TapoSession:
    """
    Represents a session for managing Tapo camera encryption and decryption.

    Attributes:
        username (Optional[str]): The username for the session.
        cnonce (Optional[str]): The client nonce used in encryption.
        nonce (Optional[str]): The server nonce used in encryption.
        device_confirm (Optional[str]): The device confirmation token.
        password (Optional[str]): The password for the session.
        hashed_password (Optional[str]): The hashed version of the password.
        lsk (Optional[bytes]): The local session key.
        ivb (Optional[bytes]): The initialization vector.
    """
    username: Optional[str] = None
    cnonce: Optional[str] = None
    nonce: Optional[str] = None
    device_confirm: Optional[str] = None

    password: Optional[str] = None
    hashed_password: Optional[str] = None

    lsk: Optional[bytes] = None  # Local session key
    ivb: Optional[bytes] = None  # Initialization vector

    def hash_password(self) -> None:
        """
        Hashes the password using SHA256 and stores it in uppercase hexadecimal format.
        """
        if self.password is None:
            raise ValueError("No camera password configured.")
        self.hashed_password = hashlib.sha256(self.password.encode("utf-8")).hexdigest().upper()

    def validate_device_confirm(self) -> bool:
        """
        Validates the device confirmation token using the session's cnonce, nonce, and hashed password.

        Returns:
            bool: True if the device confirmation token is valid, False otherwise.
        """
        if not (self.cnonce and self.nonce and self.device_confirm):
            return False
        device_confirm = (
            hashlib.sha256((self.cnonce + self.hashed_password + self.nonce).encode("utf-8")).hexdigest().upper()
            + self.nonce
            + self.cnonce
        )
        return self.device_confirm == device_confirm

    def generate_encryption_token(self, token_type: str) -> bytes:
        """
        Generates an encryption token (e.g., local session key or initialization vector).

        Args:
            token_type (str): The type of token to generate ("lsk" or "ivb").

        Returns:
            bytes: The generated encryption token.
        """
        if not (self.cnonce and self.nonce):
            raise ValueError("cnonce/nonce not set.")
        hashed_key = hashlib.sha256((self.cnonce + self.hashed_password + self.nonce).encode("utf-8")).hexdigest().upper()
        return hashlib.sha256((token_type + self.cnonce + self.nonce + hashed_key).encode("utf-8")).digest()[:16]

    def finalize_keys(self) -> None:
        """
        Finalizes the session keys by generating the local session key (lsk) and initialization vector (ivb).
        """
        self.lsk = self.generate_encryption_token("lsk")
        self.ivb = self.generate_encryption_token("ivb")

    def decrypt_b64_json(self, b64_payload: str) -> Any:
        """
        Decrypts a base64-encoded JSON payload using the session keys.

        Args:
            b64_payload (str): The base64-encoded JSON payload.

        Returns:
            Any: The decrypted JSON object.

        Raises:
            ValueError: If the session keys are not ready.
        """
        if not (self.lsk and self.ivb):
            raise ValueError("Session keys not ready.")
        raw = base64.b64decode(b64_payload)
        pt = unpad(AES.new(self.lsk, AES.MODE_CBC, self.ivb).decrypt(raw), AES.block_size)
        return json.loads(pt.decode("utf-8"))

class TapoDecryptor:
    """
    An addon class for handling Tapo camera decryption and managing session metadata.

    Attributes:
        user_agent (str): The User-Agent string for identifying Tapo camera requests.
        default_password (str): The default camera password after a factory reset.
        password (Optional[str]): The custom password from the environment variable.
        sessions (Dict[str, TapoSession]): A dictionary of sessions per host.
    """
    def __init__(self):
        """
        Initializes the TapoDecryptor addon with default settings.
        """
        self.default_password = "TPL075526460603"  # Default camera password after factory reset
        self.password = os.getenv("TAPO_PASSWORD")  # Custom password from environment variable
        self.sessions: Dict[str, TapoSession] = {}  # Session storage per host

    def _host(self, flow: http.HTTPFlow) -> str:
        """
        Retrieves the host from the HTTP flow.

        Args:
            flow (http.HTTPFlow): The HTTP flow object.

        Returns:
            str: The host of the HTTP request.
        """
        return flow.request.host

    def _ua_ok(self, flow: http.HTTPFlow) -> bool:
        """
        Checks if the User-Agent matches the expected Tapo camera client.

        Args:
            flow (http.HTTPFlow): The HTTP flow object.

        Returns:
            bool: True if the User-Agent matches, False otherwise.
        """
        return flow.request.headers.get("User-Agent", "") == USER_AGENT

    def _sess(self, flow: http.HTTPFlow) -> TapoSession:
        """
        Retrieves or creates a session for the given flow.

        Args:
            flow (http.HTTPFlow): The HTTP flow object.

        Returns:
            TapoSession: The session associated with the flow's host.
        """
        host = self._host(flow)
        if host not in self.sessions:
            self.sessions[host] = TapoSession()
        return self.sessions[host]

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Processes HTTP requests to handle login and securePassthrough methods.

        Args:
            flow (http.HTTPFlow): The HTTP flow object.
        """
        if not self._ua_ok(flow):
            return
        sess = self._sess(flow)
        try:
            req_json = json.loads(flow.request.get_text(strict=False) or "{}")
        except Exception:
            return
        m = req_json.get("method")
        if m == "login":
            params = req_json.get("params") or {}
            if params.get("encrypt_type") == "3" and "cnonce" in params:
                sess.cnonce = str(params["cnonce"]).upper()
                sess.username = params.get("username")
                flow.metadata["tapo.phase"] = "login1"
            if "digest_passwd" in params:
                flow.metadata["tapo.phase"] = "login2"
        elif m == "securePassthrough":
            if sess.lsk and sess.ivb:
                try:
                    enc = (req_json.get("params") or {}).get("request")
                    if isinstance(enc, str):
                        inner = sess.decrypt_b64_json(enc)
                        flow.metadata["tapo.request_decrypted"] = inner
                except Exception as e:
                    flow.metadata["tapo.request_error"] = "Could not decrypt request"
                    ctx.log.debug(f"Tapo request decrypt error: {e}")
            else:
                flow.metadata["tapo.request_error"] = "lsk and ivb are not set, was the login sequence captured?"

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Processes HTTP responses to handle login and securePassthrough methods.

        Args:
            flow (http.HTTPFlow): The HTTP flow object.
        """
        if not self._ua_ok(flow):
            return
        sess = self._sess(flow)
        try:
            resp_json = json.loads(flow.response.get_text(strict=False) or "{}")
        except Exception:
            return
        try:
            req_json = json.loads(flow.request.get_text(strict=False) or "{}")
        except Exception:
            req_json = {}
        m = req_json.get("method")

        if m == "login":
            result = resp_json.get("result") or {}
            data = (result.get("data") or {}) if isinstance(result, dict) else {}
            nonce = data.get("nonce")
            device_confirm = data.get("device_confirm")
            if nonce and device_confirm:
                sess.nonce = str(nonce)
                sess.device_confirm = str(device_confirm)
                sess.password = self.password
                sess.hash_password()
                if sess.validate_device_confirm():
                    sess.finalize_keys()
                    flow.metadata["tapo.phase"] = "Device password matches TAPO_PASSWORD"
                else:
                    # Try falling back to default password
                    sess.password = self.default_password
                    sess.hash_password()
                    if sess.validate_device_confirm():
                        sess.finalize_keys()
                        flow.metadata["tapo.phase"] = "Device password matches default_password"
                    else:
                        flow.metadata["tapo.phase"] = "password mismatch"
                
        if m == "securePassthrough":
            result = resp_json.get("result") or {}
            enc = result.get("response")
            if isinstance(enc, str) and sess.lsk and sess.ivb:
                try:
                    inner = sess.decrypt_b64_json(enc)
                    flow.metadata["tapo.response_decrypted"] = inner
                except Exception as e:
                    flow.metadata["tapo.response_error"] = "Could not decrypt response"
                    ctx.log.debug(f"Tapo response decrypt error: {e}")
            else:
                flow.metadata["tapo.response_error"] = "lsk and ivb are not set, was the login sequence captured?"
            # Dump flow to file for later analysis
            data = {
                "session": asdict(sess),
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "status_code": flow.response.status_code,
                "request_headers": dict(flow.request.headers),
                "response_headers": dict(flow.response.headers),
                "request_body": flow.request.get_text(),
                "response_body": flow.response.get_text(),
                "request_decrypted": flow.metadata.get("tapo.request_decrypted"),
                "response_decrypted": flow.metadata.get("tapo.response_decrypted")
            }
            with open(f"tapo_capture_{self._host(flow)}.json", "a", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=lambda o: o.hex() if isinstance(o, bytes) else str(o))
                f.write("\n")

class TapoDecryptedContentview(contentviews.Contentview):
    """
    A custom content view to display decrypted Tapo JSON data inline.
    """
    @property
    def syntax_highlight(self) -> contentviews.SyntaxHighlight:
        """
        Specifies the syntax highlighting style for the content view.

        Returns:
            contentviews.SyntaxHighlight: The syntax highlighting style ("yaml").
        """
        return "yaml"

    def render_priority(self, data: bytes, metadata: contentviews.Metadata) -> float:
        """
        Determines the priority of this content view.

        Args:
            data (bytes): The raw data of the HTTP message.
            metadata (contentviews.Metadata): The metadata of the HTTP flow.

        Returns:
            float: The priority of this content view.
        """
        flow = getattr(metadata, "flow", None)
        if not flow or not isinstance(data, (bytes, bytearray)):
            return -1
        if flow.request.headers.get("User-Agent", "") != USER_AGENT:
            return -1
        body = (data or b"").decode(errors="ignore")
        if "securePassthrough" in body or "device_confirm" in body:
            return 2.0
        if "tapo.request_decrypted" in (flow.metadata or {}) or "tapo.response_decrypted" in (flow.metadata or {}):
            return 2.0
        return -1

    def prettify(self, data: bytes, metadata: contentviews.Metadata) -> str:
        """
        Prettifies the decrypted JSON data for display.

        Args:
            data (bytes): The raw data of the HTTP message.
            metadata (contentviews.Metadata): The metadata of the HTTP flow.

        Returns:
            str: The prettified JSON string.
        """
        flow = metadata.flow
        raw_text = (data or b"").decode(errors="replace")

        def _pp(obj: Any) -> str:
            return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)

        try:
            wire = json.loads(raw_text) if raw_text.strip() else None
        except Exception:
            wire = None

        is_response = isinstance(metadata.http_message, http.Response)
        md = flow.metadata if flow else {}
        if not is_response and "tapo.request_decrypted" in md:
            wire["params"]["request_decrypted"] = md["tapo.request_decrypted"]
        if is_response and "tapo.response_decrypted" in md:
            wire["result"]["response_decrypted"] = md["tapo.response_decrypted"]

        return _pp(wire)

# Register the custom content view and addon
contentviews.add(TapoDecryptedContentview)
addons = [TapoDecryptor()]
