#!/bin/sh

. /etc/fika_manager/misc.sh
load_kdaemon_toml

get_boss_eth_wallet() {
    local json url data

    data=$(jq -rcM --null-input \
        --arg who "$kdaemon_nickname" \
        --arg where "nowhere" \
        --arg comment "activate" \
        '{ "who": $who, "where": $where, "comment": $comment }')
    url="${kdaemon_root_url}/v0/device/get_eth_wallet"
    json=$(curl -s -H "ACCESSTOKEN:${kdaemon_access_token}" -H 'Content-Type: application/json' -X GET --data-raw "$data" $url)
    fika_log debug "curl -s -H ACCESSTOKEN:${kdaemon_access_token} -H 'Content-Type: application/json' -X GET --data-raw $data $url => $json"

    if [ -n "$json" ]; then
        code=$(echo $json | jq -r .code)
        if [ "X$code" = "X200" ]; then
            wallet=$(echo $json | jq -r .data.wallet)
            if [ -n "$wallet" ]; then
                sed "s,^.*wallet_address.*$,wallet_address = \"$wallet\"," -i $KDAEMON_TOML_PATH
            fi
        else
            fika_log error "[kap][boss] GET $url error json response => ${json}"
        fi
    else
        fika_log error "[kap][boss] GET $url fail response => ${json}"
    fi
}

get_boss_ap_token() {
    local json url

    eval "$(awk '/wallet_address/ {print "walletAddress="$3}' $KDAEMON_TOML_PATH)"

    url="${kdaemon_root_url}/${kdaemon_ap_token_path}?ap_wallet=${walletAddress}"
    json=$(curl -s -H "ACCESSTOKEN:${kdaemon_access_token}" -X GET ${url})
    fika_log debug "curl -s -H ACCESSTOKEN:${kdaemon_access_token} -X GET ${url} => ${json}"

    if [ -n "$json" ]; then
        code=$(echo $json | jq -r .code)
        if [ "X$code" = "X200" ]; then
            apToken=$(echo $json | jq -r .ap_token)
            fika_log info "kap.boss.ap.token as $apToken"
            if [ -n "$apToken" ]; then
                redis-cli SET kap.boss.ap.token "$apToken"
                sed "s,^.*ap_access_token.*$,ap_access_token = \"$apToken\"," -i $KDAEMON_TOML_PATH
            fi
        fi
    fi
}

[ -z "${kdaemon_wallet_address}" -o "${kdaemon_wallet_address}" = "CHANGEME" ] && get_boss_eth_wallet
[ -z "${kdaemon_ap_access_token}" -o "${kdaemon_ap_access_token}" = "CHANGEME" ] && get_boss_ap_token
