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

## Capturing onboarding calls from Tapo App

`tapo_decrypt_pretty.py` tracks the handshake, derives session keys, and shows **decrypted inner JSON inline** for both requests and responses.

The default password for encrypt v3 firmwares is:

```
TPL075526460603
```

This can be used to dump all of the calls made to the device during on-boarding in the tapo app.

### Setup

Install dependancies

```bash
python -m venv .venv
. .venv/bin/activate
pip install pycryptodome mitmproxy frida-tools
```

Run mitmproxy once to generate certificates:

```bash
mitmproxy
```

Download httptoolkit's frida scripts

```bash
git clone https://github.com/httptoolkit/frida-interception-and-unpinning.git
cd frida-interception-and-unpinning
```

Place mitmproxy certificate in config.js:

```bash
cat ~/.mitmproxy/mitmproxy-ca-cert.pem | clipcopy
vi config.js
# Paste contents into CERT_PEM variable
```

Enable ADB debugging on target device

Install / Login to Tapo APK on target device

Connect target device to computer via USB, allow USB debugging and ensure it shows up as a device in adb:

```bash
adb devices
```

Output:

```bash
❯ adb devices
List of devices attached
JELLY20000030775        device
```

Download latest frida-server (in my case for android-arm64 target):

```bash
curl -L "$(curl -s https://api.github.com/repos/frida/frida/releases/latest | jq -r '.assets[] | select(.name|test("frida-server.*android.*arm64")) | .browser_download_url')" | xz -d > frida-server
```

Push frida-server to target device and run:

```bash
adb push frida-server /data/local/tmp && adb shell "su -c ss -ltnpK 'sport = 27042' && su -c chmod 755 /data/local/tmp/frida-server && su -c /data/local/tmp/frida-server" &
```

Forward port 8000 from device to computer:

```bash
adb reverse tcp:8000 tcp:8000
```

### Running

In one terminal, run mitmproxy capture:

```bash
cd tapo-onboarding
TAPO_PASSWORD='TPL075526460603' mitmproxy --listen-port 8000 --ssl-insecure --view-filter "~hq User-Agent:.*Tapo.*CameraClient.*Android" -s tapo_decrypt_pretty.py
```

In another terminal, inject frida scripts / launch Tapo app:

```bash
cd ../frida-interception-and-unpinning
frida -U \
    -l ./config.js \
    -l ./android/android-proxy-override.js \
    -l ./android/android-system-certificate-injection.js \
    -l ./android/android-certificate-unpinning.js \
    -l ./android/android-certificate-unpinning-fallback.js \
-f com.tplink.iot
```



Add new device in Tapo app

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


