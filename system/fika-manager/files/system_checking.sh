#!/bin/sh

code=200
message="TODO"

payload=$(jq -rcM --null-input \
    --argjson code "$code" \
    --argjson message "$message" \
    '{ "code": $code, "message": $message }')

redis-cli SET kdaemon.system.checking
