#!/bin/sh

. /etc/fika_manager/misc.sh

code=200
message="TODO"

check_ntp() {
    echo "TODO"
}

check_boss_ap_token() {
    echo "TODO"
    #apToken=$(fika_redis GET kap.boss.ap.token $accesstokenAp)
    #[ -n "$apToken" ] && return 0
    #code=400
    #message="boss ap-access-token not ready"
}

#check_ntp
#check_boss_ap_token

if payload=$(jaq -rc --null-input \
    --argjson code "$code" \
    --arg message "$message" \
    '{ "code": $code, "message": $message }'); then

    fika_redis SET kdaemon.system.checking $payload
fi
