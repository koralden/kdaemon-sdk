#!/bin/sh

. /etc/fika_manager/common.sh
. /etc/fika_manager/provision.sh library

load_kdaemon_toml

msg="nothing"
code=404
networkChg=false
DbKey="kap.por.config"

main() {
    cfg=$1 && shift

    state=$(echo "$cfg" | jq -r .state)
    orig_state=${kdaemon_state}
    if [ "X$state" != "X${orig_state}" ]; then
        if [ "X$state" = "X1" -o "X$state" = "Xon" -o "X$state" = "Xtrue" ]; then
            msg=$(wlan_guest_on)
            state="true"
        else
            msg=$(wlan_guest_off)
            state="false"
        fi
        code=200
        networkChg=true
        update_kdaemon_toml_no_dq state $state
    else
        code=201
    fi

    nickname=$(echo "$cfg" | jq -r .nickname)
    orig_nickname=${kdaemon_nickname}
    if [ "X$nickname" != "X${orig_nickname}" ]; then
        update_kdaemon_toml nickname "$nickname"

        #XXX update nickname via CMP/provistion
        provision_sync_aws
        code=200
    fi

    if [ $code -eq 200 ]; then
        fika_redis PUBLISH ${DbKey}.ack success
    else
        fika_redis PUBLISH ${DbKey}.ack fail
    fi
    $networkChg && sleep 3 && network_apply

    jq -rcM --null-input \
        --arg msg "$msg" \
        --argjson code $code \
        '{ "message": $msg, "code": $code }'
}

main "$@"
