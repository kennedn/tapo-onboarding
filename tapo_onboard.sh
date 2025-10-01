#!/usr/bin/env bash
# Tapo onboarding helper;
# - Login
# - Disable OSD logo
# - Setup RTSP / ONVIF account with username "tapoadmin" and specified password
# - Change tapo API admin password to specified password
# - Scan & connect to Wi-Fi.
#
# Requirements: bash, curl, jq, openssl, fzf, column
#
# Usage:
#   ./tapo_onboard.sh <host> <new_password>
#
# Notes:
# - Default admin password is embedded (TPL075526460603). All encrypt v3 devices use this password.

set -euo pipefail

###############################################################################
# Utilities & guards
###############################################################################

# Print an error to stderr and exit with non-zero status.
die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
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
  printf '%s' "${value}" | openssl enc -aes-128-cbc -K "${lsk}" -iv "${ivb}" -d -a -A
  echo
}

# Tapo custom header signing: sha256( sha256(hashed_password+cnonce) + payload + seq )
tapo_tag() {
  local payload=$1
  local tag
  tag=$(sha256 "${hashed_password}${cnonce}")
  sha256 "${tag}${payload}${seq}"
}

# Encrypt an arbitrary string with an RSA public key (PEM), PKCS#1 v1.5 padding, then base64
public_key_encode() {
  local pem_file=$1 value=$2
  [[ -f "${pem_file}" ]] || die "${pem_file} does not exist"
  printf '%s' "${value}" \
    | openssl pkeyutl -encrypt -inkey "${pem_file}" -pubin -pkeyopt rsa_padding_mode:pkcs1 \
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
  cnonce=$(openssl rand -hex 8 | awk '{print toupper($1)}')

  # Phase 1: request nonce + device_confirm
  local body phase1 nonce device_confirm
  body=$(jq -cn --arg cnonce "$cnonce" \
    '{method:"login",params:{cnonce:$cnonce,encrypt_type:"3",username:"admin"}}')

  phase1=$(
    curl --connect-timeout 3 -sS \
      -H "Content-Type: application/json" \
      -H 'User-Agent: Tapo CameraClient Android' \
      -kX POST -d "${body}" "${url}"
  )

  read -r nonce device_confirm <<<"$(jq -r '.result.data | [.nonce, .device_confirm] | join(" ")' <<<"${phase1}")"

  # Derivations
  hashed_password=$(sha256 "${password}")
  local hashed_key client_device_confirm digest_password
  hashed_key=$(sha256 "${cnonce}${hashed_password}${nonce}")
  client_device_confirm="${hashed_key}${nonce}${cnonce}"

  [[ "${client_device_confirm}" == "${device_confirm}" ]] || die "Password seems incorrect"

  digest_password="$(sha256 "${hashed_password}${cnonce}${nonce}")${cnonce}${nonce}"

  # Phase 2: finalise login -> get start_seq + stok
  body=$(jq -cn \
    --arg cnonce "$cnonce" \
    --arg digest_password "$digest_password" \
    '{method:"login",params:{cnonce:$cnonce,encrypt_type:"3",digest_passwd:$digest_password,username:"admin"}}')

  local phase2
  phase2=$(
    curl --connect-timeout 3 -sS \
      -H "Content-Type: application/json" \
      -H 'User-Agent: Tapo CameraClient Android' \
      -kX POST -d "${body}" "${url}"
  )

  read -r seq stok <<<"$(jq -r '.result | [.start_seq, .stok] | join(" ")' <<<"${phase2}")"

  # Session keys
  lsk=$(generate_encryption_token "lsk" "${nonce}" "${cnonce}" "${hashed_key}")
  ivb=$(generate_encryption_token "ivb" "${nonce}" "${cnonce}" "${hashed_key}")

  # Export for subshells used by command substitutions
  export hashed_password cnonce lsk ivb seq stok
}

# Atomically post-increment and print the current seq.
next_seq() {
  echo "$((seq++))"
}

# Wrap a list of inner requests in securePassthrough with encryption and headers, then decrypt response.
# $1: JSON array string of inner requests (e.g. '[{"method":"setOsd","params":{...}}]')
request() {
  local requests=$1

  local inner_body payload body raw_response encrypted_response
  inner_body=$(jq -cn --argjson requests "$requests" \
    '{method:"multipleRequest",params:{requests:$requests}}')

  payload=$(encrypt_string "${inner_body}")

  body=$(jq -cn --arg payload "$payload" \
    '{method:"securePassthrough",params:{request:$payload}}')

  raw_response=$(
    curl --connect-timeout 10 -sS \
      -H "Content-Type: application/json" \
      -H "tapo_tag: $(tapo_tag "${body}")" \
      -H "seq: $(next_seq)" \
      -H 'User-Agent: Tapo CameraClient Android' \
      -kX POST -d "${body}" \
      "${url}/stok=${stok}/ds"
  )

  encrypted_response=$(jq -r '.result.response' <<<"${raw_response}")
  decrypt_string "${encrypted_response}"
}

###############################################################################
# Device operations
###############################################################################

# Scan APs, prompt interactively to select Wifi AP via fzf, capture device public key,
# read Wi-Fi password securely, encrypt it, and return the selected AP JSON + credentials.
select_ap() {
  local response ap_table selected_ap wifi_password
  response=$(request '[{"method":"scanApList","params":{"onboarding":{"scan":{}}}}]')

  [[ "$(jq -r '.result.responses[].result.onboarding.ap_list | length' <<<"$response")" -ge 1 ]] \
    || die "No access points found."

  # Extract and save device public key for password encryption, it changes every device reset.
  jq -r '.result.responses[].result.onboarding.public_key' <<<"$response" > pubkey.pem

  # Pretty table for fzf; keep a RAW JSON column for rehydration.
  ap_table=$(
    jq -r '(["RAW","SSID"," BSSID"] | join("\u001F")),
           (.result.responses[].result.onboarding.ap_list[]
             | [@json, .ssid, " \(.bssid)"] | join("\u001F"))' <<<"$response" \
    | column -s$'\x1F' -o $'\x1F' -t
  )

  selected_ap=$(fzf --header-lines=1 -d$'\x1F' --with-nth=2.. --prompt "Select Wifi > " <<<"${ap_table}" | awk -F$'\x1f' '{print $1}')
  [[ -n "${selected_ap}" ]] || die "No AP selected."

  # Secure password prompt (no echo)
  read -r -s -p "Wifi Password: " wifi_password
  printf '\n' >&2
  wifi_password=$(public_key_encode pubkey.pem "${wifi_password}")

  # Return: selected AP object + unique_key + encrypted password
  jq -rc --arg wifi_password "${wifi_password}" '. + {unique_key:1, password:$wifi_password}' <<<"${selected_ap}"
}

# Connect to an AP using the object returned by select_ap()
connect_ap() {
  local ap_data=$1 body
  body=$(jq -cnr --argjson ap_data "${ap_data}" \
    '[{method:"connectAp",params:{onboarding:{connect:$ap_data}}}]')
  request "${body}"
}

# Turn off OSD logo overlay.
disable_logo() {
  local body
  body=$(jq -cnr \
    '[{method:"setOsd",params:{OSD:{logo:{enabled:"off",x_coor:"0",y_coor:"9150"}}}}]')
  request "${body}"
}

# Change admin password using existing session.
# Requires a public key file named pubkey.pem (downloaded by select_ap()).
change_admin_password() {
  local new_password=$1
  local hashed_new_password ciphertext body

  hashed_new_password=$(sha256 "${new_password}")
  ciphertext=$(public_key_encode pubkey.pem "${new_password}")

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
  request "${body}"
}

# Enable and set the "third account" (uses MD5 + RSA PKCS#1 ciphertext).
# Requires a static public key file named pubkey_third_account.pem (scraped from tapo APK).
change_third_account() {
  local new_password=$1
  [[ -f pubkey_third_account.pem ]] || die "pubkey_third_account.pem is required for third account changes."

  local hashed_new_password ciphertext body
  hashed_new_password=$(md5 "${new_password}")
  ciphertext=$(public_key_encode pubkey_third_account.pem "${new_password}")

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
  request "${body}"
}

###############################################################################
# Main flow
###############################################################################

main() {
  require_cmds bash curl jq openssl fzf column

  # Arguments
  local host=${1:-}
  local new_password=${2:-}
  [[ -n "${host}" && -n "${new_password}" ]] || die "Usage: $0 <host> <new_password>"

  # Default Tapo admin password (adjust if your device differs)
  local default_password='TPL075526460603'


  # 1) Login with default password
  login "${host}" "${default_password}"

  # 2) Scan/select Wi-Fi
  # Cleanup pubkey.pem on exit, downloaded by select_ap()
  trap 'rm -f pubkey.pem' EXIT
  echo "Scanning for Wifi access points..."
  local ap_data
  ap_data=$(select_ap)

  # 3) Cosmetic: disable OSD logo
  echo "Disable tapo logo"
  disable_logo

  # 4) Configure third account
  echo "Configure RTSP / ONVIF account"
  change_third_account "${new_password}"

  # 5) Change admin password
  echo "Change tapo API admin password"
  change_admin_password "${new_password}"

  # 6) Re-login with new password to refresh session keys
  login "${host}" "${new_password}"

  # 7) Connect to selected AP
  echo "Connecting to access point"
  connect_ap "${ap_data}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
