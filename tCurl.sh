#!/usr/bin/env bash
# tCurl.sh — Minimal Tapo encrypted request runner
#
# What it does:
#   1) Logs into a Tapo device (encrypt_type=3) using the provided password.
#   2) Sends the user-supplied JSON "requests" array via securePassthrough.
#   3) Prints the decrypted device response to stdout.
#
# Requirements: bash, curl, jq, openssl
#
# Usage:
#   ./tCurl.sh <host> <password> '<requests-json-array>'
#
# Example:
#   ./tCurl.sh 192.168.1.50 TPL075526460603 \
#     '[{"method":"getDeviceInfo","params":{"system":{"get_device_info":{}}}}]'
#
# Notes:
#   - <host> is the device hostname or IP (no scheme).
#   - <password> is the Tapo API admin password (default on many v3 devices is TPL075526460603).
#   - <requests-json-array> must be a valid JSON array string (single-quoted in the shell).

set -euo pipefail

###############################################################################
# Utilities
###############################################################################

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmds() {
  local missing=0
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || { printf 'Missing dependency: %s\n' "$cmd" >&2; missing=1; }
  done
  [[ "${missing}" -eq 0 ]] || die "Please install the missing dependencies above."
}

###############################################################################
# Crypto helpers
###############################################################################

# sha256 of a string -> UPPERCASE hex (as Tapo expects)
sha256() {
  local value=$1
  printf '%s' "${value}" | openssl dgst -sha256 -r | awk '{print toupper($1)}'
}

# Derive 16-byte (32 hex chars) tokens for AES key/IV from sha256(name+cnonce+nonce+hashed_key)
generate_encryption_token() {
  local name=$1 nonce=$2 cnonce=$3 hashed_key=$4
  printf '%s' "${name}${cnonce}${nonce}${hashed_key}" \
    | openssl dgst -sha256 -r \
    | awk '{print substr($1,1,32)}'
}

# AES-128-CBC base64 encode (single line). Uses globals: lsk, ivb (hex).
encrypt_string() {
  local value=$1
  printf '%s' "${value}" | openssl enc -aes-128-cbc -K "${lsk}" -iv "${ivb}" -a -A
}

# AES-128-CBC base64 decode + decrypt. Uses globals: lsk, ivb (hex).
decrypt_string() {
  local value=$1
  printf '%s' "${value}" | openssl enc -aes-128-cbc -K "${lsk}" -iv "${ivb}" -d -a -A
  echo
}

# Tapo header tag: sha256( sha256(hashed_password+cnonce) + payload + seq )
tapo_tag() {
  local payload=$1
  local tag
  tag=$(sha256 "${hashed_password}${cnonce}")
  sha256 "${tag}${payload}${seq}"
}

###############################################################################
# Session / API
###############################################################################

# Sets: url, hashed_password, cnonce, lsk, ivb, seq, stok
login() {
  local host=$1
  local password=$2

  url="https://${host}"
  export url

  # Client nonce (uppercase hex)
  cnonce=$(openssl rand -hex 8 | awk '{print toupper($1)}')

  # Phase 1: get nonce + device_confirm
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

  # Phase 2: finalize login -> start_seq + stok
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

  # Session AES key/iv (hex, 16 bytes)
  lsk=$(generate_encryption_token "lsk" "${nonce}" "${cnonce}" "${hashed_key}")
  ivb=$(generate_encryption_token "ivb" "${nonce}" "${cnonce}" "${hashed_key}")

  export hashed_password cnonce lsk ivb seq stok
}

# Post-increment sequence for the "seq" header
next_seq() {
  echo "$((seq++))"
}

# Send encrypted multipleRequest, return decrypted JSON
# $1: JSON array string of inner requests (e.g. '[{"method":"getDeviceInfo",...}]')
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

  # If device surfaces top-level error_code, fail early
  local err_code
  err_code=$(jq -r '.error_code // empty' <<<"${raw_response}")
  [[ -z "${err_code}" || "${err_code}" == "0" ]] || die "Device returned error_code=${err_code}"

  encrypted_response=$(jq -r '.result.response' <<<"${raw_response}")
  decrypt_string "${encrypted_response}"
}

###############################################################################
# Main
###############################################################################

main() {
  require_cmds bash curl jq openssl

  local host=${1:-}
  local password=${2:-}
  local requests=${3:-}

  [[ -n "${host}" && -n "${password}" && -n "${requests}" ]] \
    || die "Usage: $0 <host> <password> '<requests-json-array>'"

  login "${host}" "${password}"
  request "${requests}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi