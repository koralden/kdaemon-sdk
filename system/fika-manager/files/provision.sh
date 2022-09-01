#!/bin/sh

[ -z "$docdir" ] && docdir="/etc/fika_manager"

#[ -e /dev/log ] && logger -s -t fika-manager -p debug "[$0] docdir=$docdir"

boss_owner_info() {
    local data info code wallet

    . /etc/fika_manager/hcs_honest_challenge.sh
    db_fetch
    data="{\"ap_wallet\":\"${kapWallet}\"}"
    data=$(jq -rcM --null-input --arg wallet "$kapWallet" '{ "ap_wallet": $wallet }')

    info=$(curl -s -H "ACCESSTOKEN:${accesstoken}" -H "ACCESSTOKEN-AP:${accesstokenAp}" -H 'Content-Type: text/plain' -X GET --data-raw $data "${rootUrl}/${apInfoPath}")

    fika_log debug "[ap-info] curl -s -H \"ACCESSTOKEN:${accesstoken}\" -H \"ACCESSTOKEN-AP:${accesstokenAp}\" -H 'Content-Type: text/plain' -X GET --data-raw '$data' \"${rootUrl}/${apInfoPath}\" ==> $info"

    code=$(echo $info | jq -r .code)
    if [ "X$code" = "X200" ]; then
        wallet=$(echo $info | jq -r .data.user_wallet)
        redis-cli SET kap.boss.ap.info $(echo $info | jq -rcM .data) 2>&1 >/dev/null
        echo $wallet
        return 0
    else
        redis-cli DEL kap.boss.ap.info 2>&1 >/dev/null
        echo "null"
        return 127
    fi
}

provision_main() {
    sdk=$(fika-manager -V | awk '{print $2}')
    sdk=${sdk:-0.0.0}
    wallet=$(redis-cli get kap.core | jq -cM .wallet_address)
    nickname=$(redis-cli get kap.por.config | jq -cM .nickname)
    #XXX, jq response *null* if key nonexist
    owner=$(redis-cli GET kap.boss.ap.info | jq -cM .user_wallet)
    [ "$owner" = "null" ] && owner=$(boss_owner_info)

    jq -rcM --null-input \
        --arg sdk "$sdk" \
        --argjson wallet $wallet \
        --argjson nickname $nickname \
        --argjson owner $owner \
        '{ "sdk-version": $sdk, "ap-wallet-address": $wallet, "nickname": $nickname, "owner": $owner }'
}

provision_sync_aws() {
    payload=$(provision_main)
    fika_log debug "[provision-sync-aws] publish kap/aws/shadow/name/provision $payload ..."
    echo $payload | jq -c && redis-cli PUBLISH kap/aws/shadow/name/provision $payload
}


if [ $# -eq 0 ]; then
    provision_main
else
    [ "$1" = "sync-aws" ] && provision_sync_aws
fi
