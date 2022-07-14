#!/bin/sh

. /etc/fika_manager/common.sh

msg=""
code=404

main() {
    cfg=$1 && shift

    state=$(echo $cfg | jq -r .state)
    if [ "X$state" = "X1" -o "X$state" = "Xon" -o "X$state" = "Xtrue" ]; then
        msg=$(wlan_guest_on)
        code=200
    else
        msg=$(wlan_guest_off)
        code=200
    fi

    [ $code -eq 200 ] && network_apply
    redis-cli publish kdaemon.por.config.ack success

    jq -rcM --null-input \
        --arg msg "$msg" \
        --argjson code "$code" \
        '{ "message": $msg, "code": $code }'
}

main $@
