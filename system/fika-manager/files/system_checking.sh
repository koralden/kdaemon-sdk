#!/bin/sh

code=200
message="TODO"

check_boss_ap_token() {
    redis-cli GET kap.boss.ap.token $accesstokenAp
}

payload=$(jq -rcM --null-input \
    --argjson code "$code" \
    --arg message "$message" \
    '{ "code": $code, "message": $message }')

redis-cli SET kdaemon.system.checking $payload
