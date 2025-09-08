#!/bin/bash

generate_encryption_token() {
    local name=$1
    local nonce=$2
    local cnonce=$3
    local hashed_key=$4
    printf "%s" "${name}${cnonce}${nonce}${hashed_key}" | sha256sum | awk '{print substr($1,1,32)}'
}

encrypt_string() {
    local value=$1
    local lsk=$2
    local ivb=$3
    printf "%s" "${value}" | openssl enc -aes-128-cbc -K "${lsk}" -iv "${ivb}" -a -A
}

decrypt_string() {
    local value=$1
    local lsk=$2
    local ivb=$3
    printf "%s" "${value}" | openssl enc -aes-128-cbc -K "${lsk}" -iv "${ivb}" -d -a -A
}

tapo_tag() {
    local hashed_password=$1
    local cnonce=$2
    local seq=$3
    local payload=$4
    tag=$(printf "%s" "${hashed_password}${cnonce}" | sha256sum | awk '{print toupper($1)}')
    printf "%s" "${tag}${payload}${seq}" | sha256sum | awk '{print toupper($1)}'
}

cnonce=$(openssl rand -hex 8 | tr '[:lower:]' '[:upper:]')
url="https://${1}"
password="${2}"
JSON=$(jq -cn \
    --arg cnonce "$cnonce" \
    '{
        method: "login",
        params: {
            cnonce: $cnonce,
            encrypt_type: "3",
            username: "admin"
        }
    }'
)
login1=$(
curl --connect-timeout 3 \
    -H "Content-Type: application/json" \
    -H 'User-Agent: Tapo CameraClient Android' \
    -kX POST \
    -d "${JSON}" \
    "${url}"
)

read -r nonce device_confirm <<<"$(jq -r '.result.data | [.nonce, .device_confirm] | join(" ")' <<<"${login1}")"

hashed_password="$(printf "%s" "${password}" | sha256sum | awk '{print toupper($1)}')"
hashed_key="$(printf "%s" "${cnonce}${hashed_password}${nonce}" | sha256sum | awk '{print toupper($1)}')"
client_device_confirm="${hashed_key}${nonce}${cnonce}"

[ "${client_device_confirm}" != "${device_confirm}" ] && echo "Password seems incorrect" && exit 1

digest_password="$(printf "%s" "${hashed_password}${cnonce}${nonce}" | sha256sum | awk '{print toupper($1)}')${cnonce}${nonce}"

JSON=$(jq -cn \
    --arg cnonce "$cnonce" \
    --arg digest_password "$digest_password" \
    '{
        method: "login",
        params: {
            cnonce: $cnonce,
            encrypt_type: "3",
            digest_passwd: $digest_password,
            username: "admin"
        }
    }'
)
login2=$(
curl --connect-timeout 3 \
    -H "Content-Type: application/json" \
    -H 'User-Agent: Tapo CameraClient Android' \
    -kX POST \
    -d "${JSON}" \
    "${url}"
)

read -r seq stok <<<"$(jq -r '.result | [.start_seq, .stok] | join(" ")' <<<"${login2}")"

lsk=$(generate_encryption_token "lsk" "${nonce}" "${cnonce}" "${hashed_key}")
ivb=$(generate_encryption_token "ivb" "${nonce}" "${cnonce}" "${hashed_key}")

INNER_JSON=$(jq -cn \
    '{
      method: "multipleRequest",
      params: {
        requests: [
          {
            method: "getDeviceInfo",
            params: {
              device_info: {
                name: [
                  "basic_info"
                ]
              }
            }
          }
        ]
      }
    }'
)

payload=$(encrypt_string "${INNER_JSON}" "${lsk}" "${ivb}")

JSON=$(jq -cn \
    --arg payload "$payload" \
    '{
      method: "securePassthrough",
      params: {
        "request": $payload,
      }
    }'
)

tag=$(tapo_tag "${hashed_password}" "${cnonce}" "${seq}" "${JSON}")

raw_response=$(
curl --connect-timeout 3 \
    -H "Content-Type: application/json" \
    -H "tapo_tag: ${tag}" \
    -H "seq: ${seq}" \
    -H 'User-Agent: Tapo CameraClient Android' \
    -kX POST \
    -d "${JSON}" \
    "${url}/stok=${stok}/ds"
)

encrypted_response=$(jq -r '.result.response' <<<"${raw_response}")

decrypt_string "${encrypted_response}" "${lsk}" "${ivb}"

