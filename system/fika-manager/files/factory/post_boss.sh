#!/bin/sh

. /etc/fika_manager/misc.sh
load_kdaemon_toml

get_boss_eth_wallet() {
    local data

    data=$(jq -rcM --null-input \
        --arg who "$kdaemon_mac_address" \
        --arg where "nowhere" \
        --arg comment "activate" \
        '{ "who": $who, "where": $where, "comment": $comment }')

    if wallet=$(fika-manager boss get-ap-wallet "${data}" | jq -r .wallet); then
        if [ -n "$wallet" ]; then
            update_kdaemon_toml wallet_address "$wallet"
        fi
    else
        fika_log error "[kap][boss] GET ap-wallet fail"
    fi
}

auto_gen_wallet() {
    if wallet=$(fika-manager wallet generate); then
        [ -n "$wallet" ] && update_kdaemon_toml wallet_address "$wallet"
    else
        fika_log error "[kap][internal] generate wallet fail"
    fi
}

get_boss_ap_token() {
    local token

    eval "$(awk '/wallet_address/ {print "walletAddress="$3}' $KDAEMON_TOML_PATH)"

    if token=$(fika-manager boss -w ${walletAddress} get-ap-token | jq -r .ap_token); then
        if [ -n "$token" ]; then
            fika_log info "kap.boss.ap.token as $token"
            update_kdaemon_toml ap_access_token "$token"
            return 0
        fi
    fi
    fika_log error "[kap][boss] GET ap-access-token fail"
}

[ -z "${kdaemon_wallet_address}" -o "${kdaemon_wallet_address}" = "CHANGEME" ] && auto_gen_wallet
#[ -z "${kdaemon_ap_access_token}" -o "${kdaemon_ap_access_token}" = "CHANGEME" ] && get_boss_ap_token
