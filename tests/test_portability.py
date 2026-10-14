"""Camera-free regression tests; run with python3 -m unittest discover -s tests -v."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("TEST_BASH", "/bin/bash")
APS = [
    {"ssid": "Short", "bssid": "00:11:22:33:44:55", "rssi": -60},
    {"ssid": "Café long \"SSID\"\\name\t\n\u001f", "bssid": "aa:bb:cc:dd:ee:ff", "rssi": -30},
]

class PortabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cwd = Path(self.temp.name)

    def run_shell(self, script):
        return subprocess.run(
            [BASH, "-c", script], cwd=self.cwd, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )

    def source(self, name="tapo_onboard.sh"):
        return "source " + shlex.quote(str(ROOT / name)) + "\n"

    def selection_script(self, query="aa:bb:cc:dd:ee:ff"):
        response = {"result": {"responses": [{"error_code": 0, "result": {
            "onboarding": {"ap_list": APS, "public_key": (ROOT / "pubkey_third_account.pem").read_text()}
        }}]}}
        return self.source() + "\n".join([
            "request() { printf -v \"$2\" '%s' " + shlex.quote(json.dumps(response)) + "; }",
            "fzf() { command fzf \"$@\" --filter=" + shlex.quote(query) + "; }",
            "ap_data=$(select_ap)",
            "printf '%s\\n' \"$ap_data\"",
        ])

    def test_table_preserves_json_and_aligns_display(self):
        result = self.run_shell(self.source() + "format_ap_table <<<"
                                + shlex.quote(json.dumps(APS)))
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = result.stdout.splitlines()
        self.assertEqual(len(rows), len(APS) + 1)
        fields = [row.split("\x1f") for row in rows]
        self.assertTrue(all(len(row) == 3 for row in fields))
        self.assertEqual(len({len(row[1]) for row in fields}), 1)
        self.assertEqual(json.loads(fields[2][0]), APS[1])

    def test_real_fzf_returns_original_ap(self):
        # Exercise the actual delimiter and hidden fields without manual input.
        script = self.source() + "format_ap_table <<<" + shlex.quote(json.dumps(APS))
        script += " | fzf --header-lines=1 -d$'\\x1f' --with-nth=2.. --filter=aa:bb:cc:dd:ee:ff"
        result = self.run_shell(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout.split("\x1f")[0]), APS[1])

    def test_no_match_stops_before_password_prompt(self):
        result = self.run_shell(self.selection_script(query="does-not-exist"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ERROR: No AP selected", result.stderr)
        self.assertNotIn("Wifi Password:", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_cancelled_picker_stops_before_password_prompt(self):
        script = self.selection_script().replace(
            "ap_data=$(select_ap)", "fzf() { return 130; }\nap_data=$(select_ap)"
        )
        result = self.run_shell(script)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ERROR: No AP selected", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_empty_scan(self):
        script = self.source() + """
request() { printf -v "$2" '%s' '{"result":{"responses":[{"error_code":0,"result":{"onboarding":{"ap_list":[],"public_key":"KEY"}}}]}}'; }
ap_data=$(select_ap)
"""
        result = self.run_shell(script)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ERROR: No access points found.", result.stderr)

    def test_crypto_helpers_in_both_scripts(self):
        for name in ("tapo_onboard.sh", "tCurl.sh"):
            with self.subTest(script=name):
                result = self.run_shell(self.source(name) + """
[[ $(sha256 abc) == BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD ]]
lsk=000102030405060708090a0b0c0d0e0f
ivb=101112131415161718191a1b1c1d1e1f
plaintext='spaces, quotes " and backslash \\'
encrypted=$(encrypt_string "$plaintext")
[[ $encrypted != *$'\\n'* ]]
[[ $(decrypt_string "$encrypted") == "$plaintext" ]]
[[ $(generate_encryption_token lsk nonce cnonce hashed_key) =~ ^[0-9a-f]{32}$ ]]
""")
                self.assertEqual(result.returncode, 0, result.stderr)

    def session(self):
        return self.source() + """
lsk=000102030405060708090a0b0c0d0e0f
ivb=101112131415161718191a1b1c1d1e1f
hashed_password=HASHED
cnonce=NONCE
seq=100
url=https://camera
stok=TOKEN
"""

    def test_requests_advance_sequence_and_return_response(self):
        result = self.run_shell(self.session() + """
fixture=$(encrypt_string '{"ok":true}')
curl() {
  printf '%s\\n' "$@" >> curl-args.txt
  printf '{"error_code":0,"result":{"response":"%s"}}' "$fixture"
}
reply=''
request '[]' reply
[[ $reply == '{"ok":true}' && $seq == 101 ]]
request '[]'
[[ $seq == 102 ]]
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '{"ok":true}')
        args = (self.cwd / "curl-args.txt").read_text().splitlines()
        self.assertEqual([arg for arg in args if arg.startswith("seq: ")],
                         ["seq: 100", "seq: 101"])
        tags = [arg for arg in args if arg.startswith("tapo_tag: ")]
        bodies = [args[index + 1] for index, arg in enumerate(args) if arg == "-d"]
        prefix = hashlib.sha256(b"HASHEDNONCE").hexdigest().upper()
        expected = ["tapo_tag: " + hashlib.sha256(
            (prefix + body + str(seq)).encode()
        ).hexdigest().upper() for body, seq in zip(bodies, (100, 101))]
        self.assertEqual(tags, expected)

    def test_invalid_ciphertext_returns_failure(self):
        result = self.run_shell(self.session() + """
curl() { printf '%s' '{"error_code":0,"result":{"response":"AAAA"}}'; }
request '[]'
""")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_rsa_and_md5_helpers(self):
        result = self.run_shell(self.source() + """
[[ $(md5 abc) == 900150983CD24FB0D6963F7D28E17F72 ]]
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out private.pem 2>/dev/null
openssl pkey -in private.pem -pubout -out public.pem
plaintext='  password with \\ spaces  '
encrypted=$(public_key_encode public.pem "$plaintext")
[[ $encrypted != *$'\\n'* ]]
decrypted=$(printf '%s' "$encrypted" | openssl base64 -d -A |
  openssl pkeyutl -decrypt -inkey private.pem -pkeyopt rsa_padding_mode:pkcs1)
[[ $decrypted == "$plaintext" ]]
""")
        self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == "__main__":
    unittest.main()
