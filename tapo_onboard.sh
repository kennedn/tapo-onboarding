#!/bin/bash
set -euo pipefail

sha256() {
    local value=$1
    printf "%s" "${value}" | openssl dgst -sha256 -r | awk '{print toupper($1)}'
}

md5() {
    local value=$1
    printf "%s" "${value}" | openssl dgst -md5 -r | awk '{print toupper($1)}'
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
    printf "%s" "${value}" | openssl enc -aes-128-cbc -K "${lsk}" -iv "${ivb}" -a -A
}

decrypt_string() {
    local value=$1
    printf "%s\n" "${value}" | openssl enc -aes-128-cbc -K "${lsk}" -iv "${ivb}" -d -a -A
}

tapo_tag() {
    local payload=$1
    tag=$(sha256 "${hashed_password}${cnonce}")
    sha256 "${tag}${payload}${seq}"
}

public_key_encode() {
    local pem_file=$1
    local value=$2
    [ ! -f "${pem_file}" ] && echo "${pem_file} does not exist" && exit 1
    printf "%s" "${value}" | openssl pkeyutl -encrypt -inkey ${pem_file} -pubin -pkeyopt rsa_padding_mode:pkcs1 | base64 -w0
}

login() {
    url="https://${1}"
    local password="${2}"
    cnonce=$(openssl rand -hex 8 | awk '{print toupper($1)}')
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

    export host hashed_password cnonce lsk ivb seq stok
}

next_seq() {
    echo "$((seq++))"
}

request() {
    local requests=$1

    inner_body=$(jq -cn \
        --argjson requests "$requests" \
        '{
          method: "multipleRequest",
          params: {
            requests: $requests
          }
        }'
    )

    payload=$(encrypt_string "${inner_body}")

    body=$(jq -cn \
        --arg payload "$payload" \
        '{
          method: "securePassthrough",
          params: {
            "request": $payload,
          }
        }'
    )

    raw_response=$(
    curl --connect-timeout 10 \
        -sS \
        -H "Content-Type: application/json" \
        -H "tapo_tag: $(tapo_tag "${body}")" \
        -H "seq: $(next_seq)" \
        -H 'User-Agent: Tapo CameraClient Android' \
        -kX POST \
        -d "${body}" \
        "${url}/stok=${stok}/ds"
    )

    encrypted_response=$(jq -r '.result.response' <<<"${raw_response}")

    decrypt_string "${encrypted_response}"
}

select_ap() {
    response=$(request '[{"method":"scanApList","params":{"onboarding":{"scan":{}}}}]')

    [ "$(jq -r '.result.responses[].result.onboarding.ap_list | length' <<<"$response")" -lt 1 ] && echo "No Access points found, exiting" && exit 1

    ap_table=$(jq -r '(["RAW", "SSID", "BSSID"] | join("\u001F")),(.result.responses[].result.onboarding.ap_list[] | [@json, .ssid, .bssid] | join("\u001F"))' <<<"$response" | column -s$'\x1F' -t)
    selected_ap=$(echo "${ap_table}" | fzf --header-lines=1 --with-nth=2.. | awk '{print $1}')
    jq -r '.result.responses[].result.onboarding.public_key' <<<"$response" > pubkey.pem
    read -rsp "Wifi Password: " wifi_password
    wifi_password=$(public_key_encode pubkey.pem "${wifi_password}")
    jq -rc --arg wifi_password "${wifi_password}" '. + {unique_key: 1, password: $wifi_password}' <<<"$selected_ap"
}

connect_ap() {
    local ap_data=$1
    body=$(jq -cr --argjson ap_data "${ap_data}" '[{method: "connectAp", params: {onboarding: {connect: $ap_data}}}]' <<<"${ap_data}")
    request "${body}"
}

change_admin_password() {
    local new_password=$1

    hashed_new_password=$(sha256 "${new_password}")
    ciphertext=$(public_key_encode pubkey.pem "${new_password}")

    body=$(jq -crn \
        --arg hashed_password "${hashed_password}" \
        --arg hashed_new_password "${hashed_new_password}" \
        --arg ciphertext "${ciphertext}" \
        '[
            {
                method: "changeAdminPassword", 
                params: {
                    user_management: {
                        change_admin_password: {
                            encrypt_type: "3", 
                            secname: "root", 
                            passwd: $hashed_new_password, 
                            old_passwd: $hashed_password, 
                            ciphertext: $ciphertext, 
                            username: "admin"
                        }
                    }
                }
            }
        ]'
    )
    request "${body}"
}

change_third_account() {
    local new_password=$1

    hashed_new_password=$(md5 "${new_password}")
    ciphertext=$(public_key_encode pubkey_third_account.pem "${new_password}")

    body=$(jq -crn \
        --arg hashed_new_password "${hashed_new_password}" \
        --arg ciphertext "${ciphertext}" \
        '[
            {
              method: "setAccountEnabled",
              params: {
                user_management: {
                  set_account_enabled: {
                    enabled: "on",
                    secname: "third_account"
                  }
                }
              }
            },
            {
              method: "changeThirdAccount",
              params: {
                user_management: {
                  change_third_account: {
                    secname: "third_account",
                    passwd: $hashed_new_password,
                    old_passwd: "",
                    ciphertext: $ciphertext,
                    username: "tapoadmin"
                  }
                }
              }
            }
        ]'
    )

    request "${body}"
}

disable_logo() {
    body=$(jq -cnr \
        '[
            {
                method: "setOsd",
                params: {
                    OSD: {
                        logo: {
                            enabled: "off",
                            x_coor: "0",
                            y_coor: "9150"
                        }
                    }
                }
            }
        ]'
    )
    request "${body}"
}

main() {
    local host=$1
    # Default tapo password
    local password='TPL075526460603'
    local new_password=$2
    login "${host}" "${password}"
    ap_data=$(select_ap)
    disable_logo
    change_third_account "${new_password}"
    change_admin_password "${new_password}"
    login "${host}" "${new_password}"
    connect_ap "${ap_data}"
}

if [ "${BASH_SOURCE[0]}" == "$0" ]; then
    main "$@"
fi
