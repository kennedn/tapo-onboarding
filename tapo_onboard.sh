#!/usr/bin/env bash
# Tapo onboarding helper;
# - Login
# - Disable OSD logo
# - Setup RTSP / ONVIF account with username "tapoadmin" and specified password
# - Change tapo API admin password to specified password
# - Scan & connect to Wi-Fi.
#
# Requirements: bash (3.2+), curl, jq, openssl, fzf, awk
#
# Usage:
#   ./tapo_onboard.sh <host> <new_password>
#
# Notes:
# - Default admin password is embedded (TPL075526460603). All encrypt v3 devices use this password.

set -Eeuo pipefail

###############################################################################
# Utilities & guards
###############################################################################

# Print an error to stderr and exit with non-zero status.
die() {
  printf 'ERROR: %s%s\n' "${onboarding_step:+${onboarding_step}: }" "$*" >&2
  if [[ "${admin_password_changed:-0}" == 1 ]]; then
    printf '%s\n' 'The camera admin password was already changed. Do not rerun onboarding with the default password.' >&2
  fi
  exit 1
}

# Catch unforeseen failures too, without printing commands that contain secrets.
trap 'error_status=$?; if [[ ${BASH_SUBSHELL:-0} -eq 0 ]]; then die "Unexpected command failure at script line ${LINENO} (exit ${error_status})."; fi' ERR

# Report only response structure and numeric codes; never dump camera payloads.
check_response() {
  local json=$1 context=$2 code
  jq -e 'type == "object"' <<<"$json" >/dev/null 2>&1 \
    || die "${context}: camera returned empty, invalid, or non-object JSON."
  code=$(jq -r 'if has("error_code") then .error_code else 0 end' <<<"$json")
  [[ "$code" =~ ^-?[0-9]+$ ]] || die "${context}: invalid error_code in camera response."
  [[ "$code" == 0 ]] || die "${context}: camera returned error_code=${code}."
}

validate_request_results() {
  jq -e '.result.responses | type == "array" and length > 0 and
    all(.[]; type == "object" and (.error_code | type == "number"))' \
    <<<"$1" >/dev/null 2>&1 || die 'Camera response is missing valid result.responses entries.'
}

check_request_results() {
  local json=$1 failures
  validate_request_results "$json"
  failures=$(jq -r '.result.responses[] | select(.error_code != 0) |
    "\((.method // "unknown" | tostring | gsub("[^a-zA-Z0-9_]"; "?") | .[0:64])): error_code=\(.error_code)"' <<<"$json")
  [[ -z "$failures" ]] || die "Camera rejected operation(s): ${failures}"
}

# Ensure required executables are present.
require_cmds() {
  local missing=0
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || { printf 'Missing dependency: %s\n' "$cmd" >&2; missing=1; }
  done
  [[ "${missing}" -eq 0 ]] || die "Please install the missing dependencies above."
}

###############################################################################
# Cryptographic helpers
###############################################################################

# sha256 of a string -> uppercase hex
sha256() {
  local value=$1
  # openssl dgst -r prints "<hash> <filename>"; we take the first field and uppercase it.
  printf '%s' "${value}" | openssl dgst -sha256 -r | awk '{print toupper($1)}'
}

# md5 of a string -> uppercase hex
md5() {
  local value=$1
  printf '%s' "${value}" | openssl dgst -md5 -r | awk '{print toupper($1)}'
}

# AES session key generator (lsk/ivb): take sha256(name+cnonce+nonce+hashed_key), returns first 32 hex.
generate_encryption_token() {
  local name=$1 nonce=$2 cnonce=$3 hashed_key=$4
  printf '%s' "${name}${cnonce}${nonce}${hashed_key}" \
    | openssl dgst -sha256 -r \
    | awk '{print substr($1,1,32)}'
}

# AES-128-CBC base64 encode (no newlines). Uses global session key/IV: lsk, ivb (hex).
encrypt_string() {
  local value=$1
  # -A for single-line base64; -a to base64 encode; -K/-iv expect hex.
  printf '%s' "${value}" | openssl enc -aes-128-cbc -K "${lsk}" -iv "${ivb}" -a -A
}

# AES-128-CBC base64 decode + decrypt to plaintext. Uses lsk/ivb.
decrypt_string() {
  local value=$1
  printf '%s' "${value}" | openssl enc -aes-128-cbc -K "${lsk}" -iv "${ivb}" -d -a -A || return
  echo
}

# Tapo custom header signing: sha256( sha256(hashed_password+cnonce) + payload + seq )
tapo_tag() {
  local payload=$1
  local tag
  tag=$(sha256 "${hashed_password}${cnonce}") || return
  sha256 "${tag}${payload}${seq}"
}

# Encrypt an arbitrary string with an RSA public key (PEM), PKCS#1 v1.5 padding, then base64
public_key_encode() {
  local pem_file=$1 value=$2
  [[ -f "${pem_file}" ]] || die "${pem_file} does not exist"
  # LibreSSL loads -inkey immediately, so specify the key type first.
  printf '%s' "${value}" \
    | openssl pkeyutl -encrypt -pubin -inkey "${pem_file}" -pkeyopt rsa_padding_mode:pkcs1 \
    | openssl base64 -A
}

###############################################################################
# Session / API helpers
###############################################################################

# Globals set by login(): url, hashed_password, cnonce, lsk, ivb, seq, stok
# shellcheck disable=SC2034  # exported intentionally for subshells
login() {
  local host=$1
  local password=$2

  url="https://${host}"
  export url

  # Client nonce (uppercase hex)
  cnonce=$(openssl rand -hex 8 | awk '{print toupper($1)}') || die 'Unable to generate login nonce.'

  # Phase 1: request nonce + device_confirm
  local body phase1 nonce device_confirm
  body=$(jq -cn --arg cnonce "$cnonce" \
    '{method:"login",params:{cnonce:$cnonce,encrypt_type:"3",username:"admin"}}')

  phase1=$(
    curl --connect-timeout 3 --max-time 30 --fail -sS \
      -H "Content-Type: application/json" \
      -H 'User-Agent: Tapo CameraClient Android' \
      -kX POST -d "${body}" "${url}"
  ) || die "Login challenge HTTPS request failed (curl exit $?). Check the camera IP and Wi-Fi connection."
  # A valid challenge can carry a nonzero error_code (e.g. -40413). Preserve
  # that handshake behavior and report codes only if no challenge is present.
  jq -e 'type == "object"' <<<"$phase1" >/dev/null 2>&1 \
    || die 'Login challenge: camera returned empty, invalid, or non-object JSON.'

  local fields
  fields=$(jq -er '.result.data |
    select((.nonce | type == "string" and length > 0) and
           (.device_confirm | type == "string" and length > 0)) |
    [.nonce, .device_confirm] | @tsv' <<<"$phase1" 2>/dev/null) \
    || { check_response "$phase1" 'Login challenge';
         die 'Login challenge is missing nonce or device_confirm; this firmware may not support encrypt_type=3.'; }
  IFS=$'\t' read -r nonce device_confirm <<<"$fields"

  # Derivations
  hashed_password=$(sha256 "${password}") || die 'Unable to hash the login password.'
  local hashed_key client_device_confirm digest_password
  hashed_key=$(sha256 "${cnonce}${hashed_password}${nonce}") || die 'Unable to hash the login challenge.'
  client_device_confirm="${hashed_key}${nonce}${cnonce}"

  [[ "${client_device_confirm}" == "${device_confirm}" ]] \
    || die 'Login challenge verification failed: the admin password may differ, or the firmware may be incompatible.'

  digest_password=$(sha256 "${hashed_password}${cnonce}${nonce}") || die 'Unable to derive the login digest.'
  digest_password="${digest_password}${cnonce}${nonce}"

  # Phase 2: finalise login -> get start_seq + stok
  body=$(jq -cn \
    --arg cnonce "$cnonce" \
    --arg digest_password "$digest_password" \
    '{method:"login",params:{cnonce:$cnonce,encrypt_type:"3",digest_passwd:$digest_password,username:"admin"}}')

  local phase2
  phase2=$(
    curl --connect-timeout 3 --max-time 30 --fail -sS \
      -H "Content-Type: application/json" \
      -H 'User-Agent: Tapo CameraClient Android' \
      -kX POST -d "${body}" "${url}"
  ) || die "Login confirmation HTTPS request failed (curl exit $?)."
  check_response "$phase2" 'Login confirmation'

  fields=$(jq -er '.result |
    select((.start_seq | type == "number" and . >= 0 and floor == .) and
           (.stok | type == "string" and length > 0)) |
    [.start_seq, .stok] | @tsv' <<<"$phase2" 2>/dev/null) \
    || die 'Login confirmation is missing a valid start_seq or stok.'
  IFS=$'\t' read -r seq stok <<<"$fields"

  # Session keys
  lsk=$(generate_encryption_token "lsk" "${nonce}" "${cnonce}" "${hashed_key}") || die 'Unable to derive session key.'
  ivb=$(generate_encryption_token "ivb" "${nonce}" "${cnonce}" "${hashed_key}") || die 'Unable to derive session IV.'

  # Export for subshells used by command substitutions
  export hashed_password cnonce lsk ivb seq stok
}

# Wrap a list of inner requests in securePassthrough with encryption and headers, then decrypt response.
# $1: JSON array string of inner requests (e.g. '[{"method":"setOsd","params":{...}}]')
# $2 (optional): caller variable for the response. Use this instead of command
# substitution when making multiple requests, so sequence updates survive.
request() {
  local requests=$1

  local inner_body payload body raw_response encrypted_response plaintext request_seq=$seq signature
  jq -e 'type == "array"' <<<"$requests" >/dev/null 2>&1 || die 'Requests must be a JSON array.'
  inner_body=$(jq -cn --argjson requests "$requests" \
    '{method:"multipleRequest",params:{requests:$requests}}') || die 'Unable to build the request batch.'

  payload=$(encrypt_string "${inner_body}") || die 'Unable to encrypt camera request.'

  body=$(jq -cn --arg payload "$payload" \
    '{method:"securePassthrough",params:{request:$payload}}') || die 'Unable to build the encrypted request.'

  signature=$(tapo_tag "${body}") || die 'Unable to sign camera request.'
  raw_response=$(
    curl --connect-timeout 10 --max-time 90 --fail -sS \
      -H "Content-Type: application/json" \
      -H "tapo_tag: ${signature}" \
      -H "seq: ${seq}" \
      -H 'User-Agent: Tapo CameraClient Android' \
      -kX POST -d "${body}" \
      "${url}/stok=${stok}/ds"
  ) || die "HTTPS request failed (curl exit $?, seq=${request_seq}). Check camera connectivity; the request may already have been applied."
  seq=$((seq + 1))

  check_response "$raw_response" "Encrypted request (seq=${request_seq})"
  encrypted_response=$(jq -er '.result.response | select(type == "string" and length > 0)' <<<"${raw_response}" 2>/dev/null) \
    || die "Camera response is missing encrypted result.response."
  plaintext=$(decrypt_string "${encrypted_response}") \
    || die "Unable to decrypt camera response (seq=${request_seq}); the session may be invalid or the ciphertext malformed."
  check_response "$plaintext" "Decrypted response (seq=${request_seq})"
  if [[ -n "${2:-}" ]]; then
    printf -v "$2" '%s' "${plaintext}"
  else
    printf '%s\n' "${plaintext}"
  fi
}

# Legacy unauthenticated request
# $1: JSON array string for inner request (assumes single request) (e.g. '[{"method":"setOsd","params":{...}}]')
legacy_request() {
  local request="$1" legacy_response

  legacy_response=$(curl --connect-timeout 10 --max-time 90 --fail -sS \
    -H "Content-Type: application/json" \
    -H 'User-Agent: Tapo CameraClient Android' \
    -kX POST -d "${request}" \
    "${url}") || die "Legacy HTTPS request failed (curl exit $?)."
  check_response "$legacy_response" 'Legacy request'
  printf '%s\n' "$legacy_response"
}

# Checked mutations stop before later steps if any operation in a batch fails.
checked_request() {
  local response
  request "$1" response || return
  check_request_results "$response"
  printf '%s\n' "$response"
}

###############################################################################
# Device operations
###############################################################################

# Format AP JSON from stdin as rows for fzf. BSD column lacks GNU column's -o
# option. Keep untouched JSON in the hidden field; sanitize display labels only.
format_ap_table() {
  jq -r '
    def ssid_label: .ssid | gsub("[\u0000-\u001f\u007f]"; " ");
    def pad($width): . + (" " * ($width - length));
    ([4] + map(ssid_label | length) | max) as $width |
    (["RAW", ("SSID" | pad($width)), " BSSID"] | join("\u001f")),
    (.[] | [@json, (ssid_label | pad($width)), " \(.bssid)"] | join("\u001f"))
  '
}

# Scan APs, prompt interactively to select Wifi AP via fzf, capture device public key,
# read Wi-Fi password securely, encrypt it, and return the selected AP JSON + credentials.
# $1 (optional): caller variable for AP JSON; preserves the scan sequence update.
select_ap() {
  local response ap_list_key ap_list ap_table selected_ap wifi_password ap_json
  request '[{"method":"scanApList","params":{"onboarding":{"scan":{}}}}]' response || return
  validate_request_results "$response"
  if jq -e '.result.responses[].error_code != 0' <<<"${response}" &>/dev/null; then
    ap_list_key=".result.onboarding.scan.ap_list"
    response=$(legacy_request '{"method":"scanApList","params":{"onboarding":{"scan":{}}}}') || return
    # Hardcoded public key is used everywhere if we are legacy so just copy it
    cp pubkey_third_account.pem pubkey.pem || die 'Unable to copy the legacy public key.'
  else
    ap_list_key=".result.responses[].result.onboarding.ap_list"
    # Extract and save device public key for password encryption, it changes every device reset.
    jq -er '.result.responses[].result.onboarding.public_key | select(type == "string" and length > 0)' \
      <<<"$response" > pubkey.pem || die 'Wi-Fi scan is missing the device public key.'
  fi


  ap_list=$(jq -ec "${ap_list_key} | select(type == \"array\")" <<<"$response" 2>/dev/null) \
    || die 'Wi-Fi scan is missing a valid AP list.'
  [[ "$(jq 'length' <<<"$ap_list")" -ge 1 ]] || die 'No access points found.'
  jq -e 'all(.[]; type == "object" and (.ssid | type == "string") and (.bssid | type == "string"))' \
    <<<"$ap_list" >/dev/null 2>&1 || die 'Wi-Fi scan contains malformed AP entries.'
  openssl pkey -pubin -in pubkey.pem -noout >/dev/null 2>&1 \
    || die 'Wi-Fi scan returned an invalid device public key.'
  ap_table=$(format_ap_table <<<"$ap_list") || die "Unable to format access points."

  selected_ap=$(fzf --header-lines=1 -d$'\x1F' --with-nth=2.. --prompt "Select Wifi > " <<<"${ap_table}" | awk -F$'\x1f' '{print $1}') \
    || die "No AP selected (fzf/pipeline exit $?). Selection was cancelled or the picker failed."
  [[ -n "${selected_ap}" ]] || die "No AP selected."

  # Secure password prompt (no echo)
  IFS= read -r -s -p "Wifi Password: " wifi_password < /dev/tty \
    || die "Unable to read Wi-Fi password from terminal."
  printf '\n' >&2
  wifi_password=$(public_key_encode pubkey.pem "${wifi_password}") || die 'Unable to encrypt the Wi-Fi password.'

  # Return: selected AP object + unique_key + encrypted password
  ap_json=$(jq -rc --arg wifi_password "${wifi_password}" '. + {unique_key:1, password:$wifi_password}' <<<"${selected_ap}") || return
  if [[ -n "${1:-}" ]]; then
    printf -v "$1" '%s' "${ap_json}"
  else
    printf '%s\n' "${ap_json}"
  fi
}

# Connect to an AP using the object returned by select_ap()
connect_ap() {
  local ap_data=$1 response
  request '[{"method":"connectAp","params":{"onboarding":{"connect":'"${ap_data}"'}}}]' response || return
  validate_request_results "$response"
  if jq -e '.result.responses[].error_code != 0' <<<"$response" >/dev/null; then
    response=$(legacy_request '{"method":"connectAp","params":{"onboarding":{"connect":'"${ap_data}"'}}}') || return
  else
    check_request_results "$response"
  fi
  camera_mac=$(jq -r '[.result.onboarding.connect.mac, .result.responses[]?.result.onboarding.connect.mac] |
    map(select(type == "string" and test("^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$"))) |
    .[0] // empty | gsub("-"; ":")' <<<"$response")
  printf '%s\n' "$response"
}

# Turn off OSD logo overlay.
disable_logo() {
  local body
  body=$(jq -cnr \
    '[{method:"setOsd",params:{OSD:{logo:{enabled:"off",x_coor:"0",y_coor:"9150"}}}}]')
  checked_request "${body}"
}

# Change admin password using existing session.
# Requires a public key file named pubkey.pem (downloaded by select_ap()).
change_admin_password() {
  local new_password=$1
  local hashed_new_password ciphertext body

  hashed_new_password=$(sha256 "${new_password}")
  ciphertext=$(public_key_encode pubkey.pem "${new_password}") || die 'Unable to encrypt the new admin password.'

  body=$(jq -crn \
    --arg hashed_password "${hashed_password}" \
    --arg hashed_new_password "${hashed_new_password}" \
    --arg ciphertext "${ciphertext}" \
    '[
      { method:"changeAdminPassword",
        params:{ user_management:{ change_admin_password:{
          encrypt_type:"3", secname:"root",
          passwd:$hashed_new_password, old_passwd:$hashed_password,
          ciphertext:$ciphertext, username:"admin"
        } } } }
    ]')
  checked_request "${body}"
}

# Enable and set the "third account" (uses MD5 + RSA PKCS#1 ciphertext).
# Requires a static public key file named pubkey_third_account.pem (scraped from tapo APK).
change_third_account() {
  local new_password=$1
  [[ -f pubkey_third_account.pem ]] || die "pubkey_third_account.pem is required for third account changes."

  local hashed_new_password ciphertext body
  hashed_new_password=$(md5 "${new_password}")
  ciphertext=$(public_key_encode pubkey_third_account.pem "${new_password}") || die 'Unable to encrypt the RTSP/ONVIF password.'

  body=$(jq -crn \
    --arg hashed_new_password "${hashed_new_password}" \
    --arg ciphertext "${ciphertext}" \
    '[
      { method:"setAccountEnabled",
        params:{ user_management:{ set_account_enabled:{ enabled:"on", secname:"third_account" } } } },
      { method:"changeThirdAccount",
        params:{ user_management:{ change_third_account:{
          secname:"third_account", passwd:$hashed_new_password, old_passwd:"",
          ciphertext:$ciphertext, username:"tapoadmin"
        } } } }
    ]')
  checked_request "${body}"
}

###############################################################################
# Main flow
###############################################################################

main() {
  require_cmds bash curl jq openssl fzf awk

  # Arguments
  local host=${1:-}
  local new_password=${2:-}
  [[ -n "${host}" && -n "${new_password}" ]] || die "Usage: $0 <host> <new_password>"
  [[ -f pubkey_third_account.pem ]] \
    || die 'pubkey_third_account.pem is missing. Run from the repository directory.'

  # Default Tapo admin password (adjust if your device differs)
  local default_password='TPL075526460603'


  # 1) Login with default password
  onboarding_step='Initial login'
  admin_password_changed=0
  login "${host}" "${default_password}"

  # 2) Scan/select Wi-Fi
  # Cleanup pubkey.pem on exit, downloaded by select_ap()
  trap 'rm -f pubkey.pem' EXIT
  onboarding_step='Wi-Fi selection'
  echo "Scanning for Wifi access points..."
  local ap_data
  select_ap ap_data

  # 3) Cosmetic: disable OSD logo
  echo "Disable tapo logo"
  onboarding_step='Disable OSD logo'
  disable_logo

  # 4) Configure third account
  echo "Configure RTSP / ONVIF account"
  onboarding_step='Configure RTSP/ONVIF account'
  change_third_account "${new_password}"

  # 5) Change admin password
  echo "Change tapo API admin password"
  onboarding_step='Change admin password'
  change_admin_password "${new_password}"
  admin_password_changed=1

  # 6) Re-login with new password to refresh session keys
  onboarding_step='Login with new password'
  login "${host}" "${new_password}"

  # 7) Connect to selected AP
  echo "Connecting to access point"
  onboarding_step='Connect to Wi-Fi'
  connect_ap "${ap_data}"
  printf '%s\n' \
    'Wi-Fi connection request accepted. The camera setup Wi-Fi may now disappear.' \
    'Reconnect your computer to your home Wi-Fi, wait about a minute, and find the camera in your router client list.'
  [[ -z "${camera_mac:-}" ]] || printf 'Camera MAC: %s\n' "$camera_mac"
  printf '%s\n' \
    'RTSP/ONVIF username: tapoadmin. Use the camera password you supplied to this script.' \
    'Confirm the camera joined your network before treating provisioning as complete. Do not rerun onboarding with the default password.'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
