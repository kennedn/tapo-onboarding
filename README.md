# Tapo-Onboarding

Tools and notes for onboarding TP-Link Tapo cameras that use the v3 encryption method **without cloud dependency** and for **reverse-engineering** their local protocol. This repo contains:

* A PoC Bash client that performs the two-phase login, derives AES keys, builds a `securePassthrough` request, and decrypts the response.
* A `mitmproxy` addon + content view that automatically decrypts and pretty-prints Tapo traffic during interactive RE.

---

## Contents

```
.
├── tapo_login.sh              # PoC login + encrypted request/response test
├── tapo_decrypt_pretty.py     # mitmproxy addon: handshake tracking + AES decrypt + inline view
└── README.md
```

---

## Protocol Overview (high level)

1. Client POSTs `{"method":"login","params":{"cnonce":...,"encrypt_type":"3","username":"admin"}}`.
2. Device replies with `{ data: { nonce, device_confirm } }`.
3. Client validates `device_confirm` and derives:

   * `hashed_password = SHA256(password).upper()`
   * `hashed_key = SHA256(cnonce + hashed_password + nonce).upper()`
   * Session tokens:
     `lsk = SHA256("lsk" + cnonce + nonce + hashed_key)[0:16]`
     `ivb = SHA256("ivb" + cnonce + nonce + hashed_key)[0:16]`
4. Client sends second `login` with `digest_passwd = SHA256(hashed_password + cnonce + nonce).upper() + cnonce + nonce`.
5. Subsequent API calls go via `{"method":"securePassthrough","params":{"request": base64(AES-128-CBC(lsk, ivb, json))}}` and are accompanied by `tapo_tag`/`seq` headers.

---

## Prerequisites

* Linux/Mac with Bash, `jq`, `curl`, `openssl`
* Python 3.10+ for RE tooling
* `mitmproxy` 10+
* `pycryptodome` for AES (`pip install pycryptodome`)

---

## Login & Request (tapo\_login.sh)

The script performs login, derives keys, requests `getDeviceInfo`, and decrypts the `securePassthrough` result.

### Usage

```bash
chmod +x tapo_login.sh
./tapo_login.sh <camera-host-or-ip> '<camera-password>'
```

Example:

```bash
./tapo_login.sh 192.168.1.50 'your-camera-password'
```

---

## Live Decrypt & Pretty View (mitmproxy)

`tapo_decrypt_pretty.py` tracks the handshake, derives session keys, and shows **decrypted inner JSON inline** for both requests and responses.

### Install

```bash
pip install mitmproxy pycryptodome
```

### Run

Export your camera password for the addon to compute confirmation digests:

```bash
export TAPO_PASSWORD='your-camera-password'
mitmproxy -s tapo_decrypt_pretty.py
```

Point your Tapo client or your script to mitmproxy (HTTP(S) proxy). The addon:

* Detects Tapo traffic via `User-Agent: Tapo CameraClient Android`.
* Captures `cnonce`, `nonce`, and `device_confirm`.
* Validates the handshake (MD5 or SHA256 variant).
* Derives `lsk`/`ivb` and transparently decrypts `securePassthrough`.
* Adds `request_decrypted` / `response_decrypted` fields to the body view.

You’ll see clean, pretty-printed JSON in mitmproxy for fast diffing and exploration.


