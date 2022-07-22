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

wallet=$(echo $json | jq -r .wallet_address)

sed -i "s,-w .* ,-w $wallet ," /etc/init.d/fika-easy-setup

dbUrl=$(echo $json | jq -r .database_url)
dbServer=$(echo $dbUrl | awk -F: '{gsub("//", "", $2); print $2}')
dbPort=$(echo $dbUrl | awk -F: '{print $3}')
sed -e "s,^port .*$,port $dbPort," \
    -e "s,^pidfile /var/run/redis_.*.pid$,pidfile /var/run/redis_${dbPort}.pid," \
    -e "s,^bind .*$,bind ${dbServer}," \
    -i /etc/fika-redis.conf
sed -i "s,^database = .*$,database = \"${dbUrl}\"," /etc/fika_manager/config.toml
sed -e "s,server  : .*$,server  : ${dbServer}," \
    -e "s,port    : .*$,port    : ${dbPort}," \
    -i /etc/fika_iot_gateway/fika_iot_gateway.yaml

redis-cli SET $key.done ok
