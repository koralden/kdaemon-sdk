#!/bin/sh

json=$1 && shift
key=$1 && shift

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
    -i /etc/fika_iot_gateway/config.yaml
