#!/bin/bash
set -euo pipefail

sha256() {
    local value=$1
    printf "%s" "${value}" | openssl dgst -sha256 -r | awk '{print toupper($1)}'
}

generate_encryption_token() {
    local name=$1
    local nonce=$2
    local cnonce=$3
    local hashed_key=$4
    printf "%s" "${name}${cnonce}${nonce}${hashed_key}" | openssl dgst -sha256 -r | awk '{print substr($1,1,32)}'
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
    tag=$(printf "%s" "${hashed_password}${cnonce}" | openssl dgst -sha256 -r | awk '{print toupper($1)}')
    printf "%s" "${tag}${payload}${seq}" | openssl dgst -sha256 -r | awk '{print toupper($1)}'
}

login() {
    local url="https://${1}"
    local password="${2}"
    local cnonce=$(openssl rand -hex 8 | awk '{print toupper($1)}')
    body=$(jq -cn \
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
    phase1=$(
    curl --connect-timeout 3 \
        -sS \
        -H "Content-Type: application/json" \
        -H 'User-Agent: Tapo CameraClient Android' \
        -kX POST \
        -d "${body}" \
        "${url}"
    )
    read -r nonce device_confirm <<<"$(jq -r '.result.data | [.nonce, .device_confirm] | join(" ")' <<<"${phase1}")"

    hashed_password=$(sha256 "${password}")
    hashed_key=$(sha256 "${cnonce}${hashed_password}${nonce}")
    client_device_confirm="${hashed_key}${nonce}${cnonce}"

    [ "${client_device_confirm}" != "${device_confirm}" ] && echo "Password seems incorrect" && exit 1

    digest_password="$(sha256 "${hashed_password}${cnonce}${nonce}")${cnonce}${nonce}"

    body=$(jq -cn \
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

    phase2=$(
    curl --connect-timeout 3 \
        -sS \
        -H "Content-Type: application/json" \
        -H 'User-Agent: Tapo CameraClient Android' \
        -kX POST \
        -d "${body}" \
        "${url}"
    )

    read -r seq stok <<<"$(jq -r '.result | [.start_seq, .stok] | join(" ")' <<<"${phase2}")"

    lsk=$(generate_encryption_token "lsk" "${nonce}" "${cnonce}" "${hashed_key}")
    ivb=$(generate_encryption_token "ivb" "${nonce}" "${cnonce}" "${hashed_key}")

    echo "${hashed_password} ${cnonce} ${lsk} ${ivb} ${seq} ${stok}"
}

getDeviceInfo() {
    local url="https://${1}"
    local hashed_password=$2
    local cnonce=$3
    local lsk=$4
    local ivb=$5
    local seq=$6
    local stok=$7

    inner_body=$(jq -cn \
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

    payload=$(encrypt_string "${inner_body}" "${lsk}" "${ivb}")

    body=$(jq -cn \
        --arg payload "$payload" \
        '{
          method: "securePassthrough",
          params: {
            "request": $payload,
          }
        }'
    )

    tag=$(tapo_tag "${hashed_password}" "${cnonce}" "${seq}" "${body}")

    raw_response=$(
    curl --connect-timeout 3 \
        -sS \
        -H "Content-Type: application/json" \
        -H "tapo_tag: ${tag}" \
        -H "seq: ${seq}" \
        -H 'User-Agent: Tapo CameraClient Android' \
        -kX POST \
        -d "${body}" \
        "${url}/stok=${stok}/ds"
    )

    encrypted_response=$(jq -r '.result.response' <<<"${raw_response}")

    decrypt_string "${encrypted_response}" "${lsk}" "${ivb}"
}

main() {
    local host=$1
    local password=$2
    read -r hashed_password cnonce lsk ivb seq stok  <<<"$(login "${host}" "${password}")"
    getDeviceInfo "${host}" "${hashed_password}" "${cnonce}" "${lsk}" "${ivb}" "${seq}" "${stok}"
}

if [ "${BASH_SOURCE[0]}" == "$0" ]; then
    main "$@"
fi
