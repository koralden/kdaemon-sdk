#!/bin/sh

# {cmd} {arg...}

logger -s -t fika-manager -p debug "[$0] $@"

payload=$1 && shift

code=404
resp="fail"

cmd=$(echo $payload | jq -r .command)

#$("$@")
#eval $@ >/dev/null
#[ $? -eq 0 ] && code=200 && resp="ok"

if [ -n "$cmd" ]; then
    resp=$($cmd)
    [ $? -eq 0 ] && code=200
    logger -s -t fika-manager -p info "[$0] run $cmd ... $code"
fi

feedback=$(jq -rcM --null-input \
    --arg msg "$resp" \
    --argjson code "$code" \
    '{ "message": $msg, "code": $code }')

#TODO, better use internal IPC channel
fika_redis publish kap/aws/shadow/name/remote-manage "$feedback"
echo $feedback
