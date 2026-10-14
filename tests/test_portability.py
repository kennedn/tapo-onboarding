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

    def test_request_errors_are_not_reported_as_bad_decrypt(self):
        for response, error in (
            ({"error_code": -40401}, "error_code=-40401"),
            ({"error_code": 0, "result": {}}, "missing encrypted result.response"),
        ):
            with self.subTest(response=response):
                script = self.session() + "curl() { printf '%s' "
                script += shlex.quote(json.dumps(response)) + "; }\nrequest '[]'"
                result = self.run_shell(script)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)
                self.assertNotIn("bad decrypt", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_invalid_ciphertext_returns_failure(self):
        result = self.run_shell(self.session() + """
curl() { printf '%s' '{"error_code":0,"result":{"response":"AAAA"}}'; }
request '[]'
""")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("Unable to decrypt camera response (seq=100)", result.stderr)

    def test_request_transport_failure_has_context(self):
        result = self.run_shell(self.session() + "curl() { return 28; }; request '[]'")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTPS request failed (curl exit 28, seq=100)", result.stderr)
        self.assertNotIn("bad decrypt", result.stderr)

    def test_malformed_responses_do_not_leak_payloads(self):
        for response in ('', 'TOP-SECRET', '[]', '{"error_code":"TOP-SECRET"}',
                         '{"error_code":false}', '{"error_code":null}'):
            with self.subTest(response=response):
                script = self.session() + "curl() { printf '%s' "
                script += shlex.quote(response) + "; }; request '[]'"
                result = self.run_shell(script)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ERROR:", result.stderr)
                self.assertNotIn("TOP-SECRET", result.stderr + result.stdout)

    def test_invalid_decrypted_json_is_reported(self):
        result = self.run_shell(self.session() + """
fixture=$(encrypt_string 'TOP-SECRET')
curl() { printf '{"error_code":0,"result":{"response":"%s"}}' "$fixture"; }
request '[]'
""")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Decrypted response (seq=100)", result.stderr)
        self.assertNotIn("TOP-SECRET", result.stderr + result.stdout)

    def login_fixture(self, confirmation='{"error_code":0,"result":{"start_seq":100,"stok":"TOKEN"}}'):
        return self.source() + """
curl() {
  if [[ "$*" == *digest_passwd* ]]; then
    printf '%s' """ + shlex.quote(confirmation) + """
  else
    local confirm
    confirm="$(sha256 "${cnonce}$(sha256 fixture-password)NONCE")NONCE${cnonce}"
    jq -cn --arg confirm "$confirm" \
      '{error_code:-40413,result:{data:{nonce:"NONCE",device_confirm:$confirm}}}'
  fi
}
"""

    def test_login_accepts_nonzero_challenge_code(self):
        result = self.run_shell(self.login_fixture() + """
login camera fixture-password
[[ $seq == 100 && $stok == TOKEN && ${#lsk} == 32 && ${#ivb} == 32 ]]
""")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_login_confirmation_errors(self):
        for confirmation, message in (
            ('{"error_code":-40209}', "Login confirmation: camera returned error_code=-40209"),
            ('{"result":{"start_seq":null,"stok":"TOP-SECRET"}}', "valid start_seq or stok"),
            ('{"result":{"start_seq":-1,"stok":"TOP-SECRET"}}', "valid start_seq or stok"),
            ('{"result":{"start_seq":0,"stok":null}}', "valid start_seq or stok"),
        ):
            with self.subTest(confirmation=confirmation):
                result = self.run_shell(self.login_fixture(confirmation) + "login camera fixture-password")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertNotIn("TOP-SECRET", result.stderr + result.stdout)

    def test_login_challenge_errors(self):
        for response, message in (
            ('{"error_code":-40209}', "error_code=-40209"),
            ('{}', "missing nonce or device_confirm"),
            ('TOP-SECRET', "invalid, or non-object JSON"),
        ):
            with self.subTest(response=response):
                result = self.run_shell(self.source() + "curl() { printf '%s' "
                                        + shlex.quote(response) + "; }; login camera fixture-password")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertNotIn("TOP-SECRET", result.stderr + result.stdout)
        result = self.run_shell(self.source() + "curl() { return 7; }; login camera fixture-password")
        self.assertIn("Login challenge HTTPS request failed (curl exit 7)", result.stderr)

    def test_batch_errors_stop_mutations(self):
        result = self.run_shell(self.source() + """
request() { printf -v "$2" '%s' '{"result":{"responses":[{"method":"setAccountEnabled","error_code":0},{"method":"changeThirdAccount","error_code":-1}]}}'; }
checked_request '[]'
printf SHOULD_NOT_CONTINUE
""")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("changeThirdAccount: error_code=-1", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_legacy_connect_success_and_failure(self):
        for code in (0, -1):
            with self.subTest(code=code):
                response = {"error_code": code, "result": {"onboarding": {
                    "connect": {"mac": "ec-b9-31-16-ff-b1"}}}}
                script = self.source() + """
request() { printf -v "$2" '%s' '{"result":{"responses":[{"method":"connectAp","error_code":-1}]}}'; }
url=https://camera
curl() { printf '%s' """ + shlex.quote(json.dumps(response)) + "; }\nconnect_ap '{}'"
                result = self.run_shell(script)
                if code == 0:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout), response)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Legacy request: camera returned error_code=-1", result.stderr)
                    self.assertEqual(result.stdout, "")

    def main_fixture(self):
        (self.cwd / "pubkey_third_account.pem").write_text((ROOT / "pubkey_third_account.pem").read_text())
        return self.source() + """
login() { :; }
select_ap() { printf -v "$1" '%s' '{}'; }
disable_logo() { :; }
change_third_account() { :; }
change_admin_password() { :; }
connect_ap() { camera_mac=ec:b9:31:16:ff:b1; }
"""

    def test_main_explains_successful_wifi_handoff(self):
        result = self.run_shell(self.main_fixture() + "main camera fixture-password")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("setup Wi-Fi may now disappear", result.stdout)
        self.assertIn("Camera MAC: ec:b9:31:16:ff:b1", result.stdout)
        self.assertNotIn("fixture-password", result.stdout + result.stderr)

    def test_main_reports_stage_and_changed_password(self):
        result = self.run_shell(self.main_fixture() + """
connect_ap() { die 'fixture failure'; }
main camera fixture-password
""")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ERROR: Connect to Wi-Fi: fixture failure", result.stderr)
        self.assertIn("admin password was already changed", result.stderr)
        self.assertNotIn("connection request accepted", result.stdout)

    def test_unexpected_failure_reports_stage_without_command(self):
        result = self.run_shell(self.source() + """
onboarding_step='Fixture step'
unexpected() { false TOP-SECRET; }
unexpected
""")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ERROR: Fixture step: Unexpected command failure at script line", result.stderr)
        self.assertIn("exit 1", result.stderr)
        self.assertNotIn("TOP-SECRET", result.stderr + result.stdout)

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
