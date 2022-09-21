#!/bin/sh

. /etc/fika_manager/common.sh
. /etc/fika_manager/provision.sh library

msg="nothing"
code=404

main() {
    cfg=$1 && shift
    orig=$(redis-cli --raw GET kap.por.config.old)

    state=$(echo "$cfg" | jq -r .state)
    orig_state=$(echo "$orig" | jq -r .state)
    if [ "X$state" != "X${orig_state}" ]; then
        if [ "X$state" = "X1" -o "X$state" = "Xon" -o "X$state" = "Xtrue" ]; then
            msg=$(wlan_guest_on)
            code=200
        else
            msg=$(wlan_guest_off)
            code=200
        fi
    else
        code=201
    fi

    nickname=$(echo "$cfg" | jq -r .nickname)
    orig_nickname=$(echo "$orig" | jq -r .nickname)
    if [ "X$nickname" != "X${orig_nickname}" ]; then
        #XXX update nickname via CMP/provistion
        provision_sync_aws
    fi

    [ $code -eq 200 ] && network_apply

    redis-cli SAVE
    redis-cli PUBLISH kap.por.config.ack success

    jq -rcM --null-input \
        --arg msg "$msg" \
        --argjson code $code \
        '{ "message": $msg, "code": $code }'
}

main "$@"
