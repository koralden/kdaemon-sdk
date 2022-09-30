#!/bin/sh

. /etc/fika_manager/misc.sh
load_kdaemon_toml

[ -z "$docdir" ] && docdir="/etc/fika_manager"

#[ -e /dev/log ] && logger -s -t fika-manager -p debug "[$0] docdir=$docdir"

boss_owner_info() {
    local data info code wallet

    #. /etc/fika_manager/hcs_honest_challenge.sh
    #db_fetch
    data=$(jq -rcM --null-input --arg wallet "${kdaemon_wallet_address}" '{"ap_wallet": $wallet}')

    info=$(curl -s -H "ACCESSTOKEN:${kdaemon_access_token}" -H "ACCESSTOKEN-AP:${kdaemon_ap_access_token}" -H 'Content-Type: text/plain' -X GET --data-raw $data "${kdaemon_root_url}/${kdaemon_ap_info_path}")

    fika_log debug "curl -s -H ACCESSTOKEN:${kdaemon_access_token} -H ACCESSTOKEN-AP:${kdaemon_ap_access_token} -H 'Content-Type: text/plain' -X GET --data-raw $data ${kdaemon_root_url}/${kdaemon_ap_info_path} => ${info}"

    code=$(echo $info | jq -r .code)
    if [ "X$code" = "X200" ]; then
        wallet=$(echo $info | jq -r .data.user_wallet)
        echo $wallet
        return 0
    else
        echo "null"
        return 127
    fi
}

provision_main() {
    sdk=$(fika-manager -V | awk '{print $2}')
    sdk=${sdk:-0.0.0}
    wallet="${kdaemon_wallet_address}"
    nickname="${kdaemon_nickname}"
    owner="${kdaemon_user_wallet}"
    [ -z "$owner" -o "X$owner" = "Xnull" ] && owner=$(boss_owner_info)

    jq -rcM --null-input \
        --arg sdk "$sdk" \
        --arg wallet "$wallet" \
        --arg nickname "$nickname" \
        --arg owner "$owner" \
        '{ "sdk-version": $sdk, "ap-wallet-address": $wallet, "nickname": $nickname, "owner": $owner }'
}

provision_sync_aws() {
    load_kdaemon_toml

    # flow: other call ->
    #       this(publish kap/aws/shadow/name/provision) ->
    #       manager/aws-iot(subscribe)
    # TODO, better use rule.toml's subscribe 'provision' to output aws
    payload=$(provision_main)
    eval $(awk '/^topic.*provision/ {print "provisionTopic="$3}' /etc/fika_manager/rule.toml)
    ipcKey="$provisionTopic"
    if [ -n "$ipcKey" ]; then
        fika_log debug "[provision-sync-aws] publish $ipcKey $payload ..."
        echo $payload | jq -c && fika_redis PUBLISH $ipcKey "$payload"
    fi
}


if [ $# -eq 0 ]; then
    provision_main
else
    [ "$1" = "sync-aws" ] && provision_sync_aws
fi
