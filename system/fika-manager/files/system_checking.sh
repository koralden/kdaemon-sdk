#!/bin/sh

code=200
message="TODO"

check_ntp() {
    echo "TODO"
}

check_boss_ap_token() {
    apToken=$(redis-cli GET kap.boss.ap.token $accesstokenAp)

    [ -n "$apToken" ] && return 0

    . /etc/fika_manager/easy_setup.sh
    get_boss_ap_token
}

#check_ntp
#check_boss_ap_token

payload=$(jq -rcM --null-input \
    --argjson code "$code" \
    --arg message "$message" \
    '{ "code": $code, "message": $message }')

redis-cli SET kdaemon.system.checking $payload
