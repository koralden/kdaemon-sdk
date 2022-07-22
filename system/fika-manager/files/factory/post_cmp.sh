#!/bin/sh

DEBUG=0

my_log() {
    level=$1 && shift

    if [ -e /dev/log ]; then
        logger -s -t fika-manager-recovery -p ${level} "$@"
    else
        echo "[fika-manager-recovery][${level}] $@"
    fi

    [ $DEBUG -eq 1 ] && echo "[fika-manager-recovery][${level}] $@" >>/tmp/factory.log
}

my_log debug "[$0] $@"

json=$1 && shift
key=$1 && shift

[ $(redis-cli EXISTS $key.done) -ne 0 ] && exit 0

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
    /etc/fika_iot_gateway/fika_iot_gateway.yaml

redis-cli SET $key.done ok
