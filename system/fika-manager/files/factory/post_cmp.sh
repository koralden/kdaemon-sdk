#!/bin/sh

. /etc/fika_manager/misc.sh

fika_log debug "[$0] $@"

json=$1 && shift
key=$1 && shift

endpoint=$(echo $json | jq .endpoint)
port=$(echo $json | jq -r .port)
thing=$(echo $json | jq .thing)
cert=$(echo $json | jq .cert)
pkey=$(echo $json | jq .key)
ca=$(echo $json | jq .ca)

sed -i -e "s,port,xport," \
    -e "s,endpoint  : .*$,endpoint  : $endpoint," \
    -e "s,port      : .*$,port      : $port," \
    -e "s,cert      : .*$,cert      : $cert," \
    -e "s,key       : .*$,key       : $pkey," \
    -e "s,ca        : .*$,ca        : $ca," \
    -e "s,thing     : .*$,thing     : $thing," \
    -e "s,xport,port," \
    /etc/fika_iot_gateway/config.yaml
