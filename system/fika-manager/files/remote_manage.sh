#!/bin/sh

# {cmd} {arg...}

code=404
resp="fail"

#$("$@")
#eval $@ >/dev/null
#[ $? -eq 0 ] && code=200 && resp="ok"

resp=$($@)
[ $? -eq 0 ] && code=200

jq -rcM --null-input \
    --arg msg "$resp" \
    --argjson code "$code" \
    '{ "message": $msg, "code": $code }'
