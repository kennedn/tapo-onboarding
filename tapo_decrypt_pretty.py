# tapo_decrypt_view.py
# Show Tapo decrypted JSON inline via a custom mitmproxy content view + handshake/decrypt addon.

import os
import json
import base64
import hashlib
from dataclasses import dataclass
from typing import Optional, Dict, Any

from mitmproxy import http, ctx, contentviews
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

UA = "Tapo CameraClient Android"

class EncryptionMethod:
    MD5 = "MD5"
    SHA256 = "SHA256"

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()

@dataclass
class TapoSession:
    username: Optional[str] = None
    cnonce: Optional[str] = None
    nonce: Optional[str] = None
    device_confirm: Optional[str] = None

    password: Optional[str] = None
    hashed_md5: Optional[str] = None
    hashed_sha256: Optional[str] = None

    encryption_method: Optional[str] = None
    lsk: Optional[bytes] = None
    ivb: Optional[bytes] = None
    ready: bool = False

    def ensure_password_hashes(self) -> None:
        if self.password is None:
            raise ValueError("No camera password configured.")
        if not self.hashed_md5:
            self.hashed_md5 = hashlib.md5(self.password.encode("utf-8")).hexdigest().upper()
        if not self.hashed_sha256:
            self.hashed_sha256 = hashlib.sha256(self.password.encode("utf-8")).hexdigest().upper()

    def validate_device_confirm(self) -> bool:
        if not (self.cnonce and self.nonce and self.device_confirm):
            return False
        self.ensure_password_hashes()
        sha_variant = sha256_hex((self.cnonce + self.hashed_sha256 + self.nonce).encode("utf-8"))
        if self.device_confirm == (sha_variant + self.nonce + self.cnonce):
            self.encryption_method = EncryptionMethod.SHA256
            return True
        md5_variant = sha256_hex((self.cnonce + self.hashed_md5 + self.nonce).encode("utf-8"))
        if self.device_confirm == (md5_variant + self.nonce + self.cnonce):
            self.encryption_method = EncryptionMethod.MD5
            return True
        return False

    def get_hashed_password(self) -> str:
        if self.encryption_method == EncryptionMethod.MD5:
            return self.hashed_md5  # type: ignore
        if self.encryption_method == EncryptionMethod.SHA256:
            return self.hashed_sha256  # type: ignore
        raise ValueError("Encryption method not established.")

    def generate_encryption_token(self, token_type: str) -> bytes:
        if not (self.cnonce and self.nonce):
            raise ValueError("cnonce/nonce not set.")
        hp = self.get_hashed_password()
        hashedKey = sha256_hex((self.cnonce + hp + self.nonce).encode("utf-8"))
        return hashlib.sha256((token_type + self.cnonce + self.nonce + hashedKey).encode("utf-8")).digest()[:16]

    def finalize_keys(self) -> None:
        if self.encryption_method is None:
            raise ValueError("Encryption method unknown.")
        self.lsk = self.generate_encryption_token("lsk")
        self.ivb = self.generate_encryption_token("ivb")

    def decrypt_b64_json(self, b64_payload: str) -> Any:
        if not (self.lsk and self.ivb):
            raise ValueError("Session keys not ready.")
        raw = base64.b64decode(b64_payload)
        pt = unpad(AES.new(self.lsk, AES.MODE_CBC, self.ivb).decrypt(raw), AES.block_size)
        return json.loads(pt.decode("utf-8"))

class TapoDecryptor:
    def __init__(self):
        self.password = os.getenv("TAPO_PASSWORD")
        self.sessions: Dict[str, TapoSession] = {}

    def _host(self, flow: http.HTTPFlow) -> str:
        return flow.request.host

    def _ua_ok(self, flow: http.HTTPFlow) -> bool:
        return flow.request.headers.get("User-Agent", "") == UA

    def _sess(self, flow: http.HTTPFlow) -> TapoSession:
        host = self._host(flow)
        if host not in self.sessions:
            self.sessions[host] = TapoSession(password=self.password)
        return self.sessions[host]

    def request(self, flow: http.HTTPFlow) -> None:
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
                if sess.validate_device_confirm():
                    sess.finalize_keys()
                    sess.ready = True
                    flow.metadata["tapo.phase"] = "Device password matches TAPO_PASSWORD"
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

# -------- Custom content view: show decrypted JSON inline ---------------------

class TapoDecryptedContentview(contentviews.Contentview):
    # YAML highlighter works nicely for JSON. (mitmproxy recommends YAML for JSON highlighting.)
    # https://docs.mitmproxy.org/stable/api/mitmproxy/contentviews.html
    @property
    def syntax_highlight(self) -> contentviews.SyntaxHighlight:
        return "yaml"

    def render_priority(self, data: bytes, metadata: contentviews.Metadata) -> float:
        flow = getattr(metadata, "flow", None)
        if not flow or not isinstance(data, (bytes, bytearray)):
            return -1
        if flow.request.headers.get("User-Agent", "") != UA:
            return -1
        # Prefer this view if decrypted artefacts are present or body is a Tapo JSON envelope.
        body = (data or b"").decode(errors="ignore")
        if "securePassthrough" in body or "device_confirm" in body:
            return 2.0
        if "tapo.request_decrypted" in (flow.metadata or {}) or "tapo.response_decrypted" in (flow.metadata or {}):
            return 2.0
        return -1

    def prettify(self, data: bytes, metadata: contentviews.Metadata) -> str:
        flow = metadata.flow
        raw_text = (data or b"").decode(errors="replace")

        def _pp(obj: Any) -> str:
            return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)

        # Try parse on-wire JSON to reformat.
        try:
            wire = json.loads(raw_text) if raw_text.strip() else None
        except Exception:
            wire = None

        # Decide whether this is request or response body.
        is_response = isinstance(metadata.http_message, http.Response)

        # Append decrypted inner JSON if available.
        md = flow.metadata if flow else {}
        if not is_response and "tapo.request_decrypted" in md:
            wire["params"]["request_decrypted"] = md["tapo.request_decrypted"]
        if is_response and "tapo.response_decrypted" in md:
            wire["result"]["response_decrypted"] = md["tapo.response_decrypted"]

        return _pp(wire)

# Register content view and addon
contentviews.add(TapoDecryptedContentview)
addons = [TapoDecryptor()]

