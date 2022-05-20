#!/bin/sh

. /etc/fika_manager/misc.sh

load_kdaemon_toml

dbUrl="${kdaemon_database}"
dbServer=$(echo $dbUrl | awk -F: '{gsub("//", "", $2); print $2}')
dbPort=$(echo $dbUrl | awk -F: '{print $3}')
[ -e /etc/fika-redis.conf ] && sed -e "s,^port .*$,port $dbPort," \
    -e "s,^pidfile /var/run/redis_.*.pid$,pidfile /var/run/redis_${dbPort}.pid," \
    -e "s,^bind .*$,bind ${dbServer}," \
    -i /etc/fika-redis.conf

mac=$(ip link show dev eth0 | awk '/link/ {print tolower($2)}')
if [ -z "${kdaemon_mac_address}" -o "${kdaemon_mac_address}" = "CHANGEME" ]; then
    update_kdaemon_toml mac_address $mac
fi

if [ -z "${kdaemon_serial_number}" -o "${kdaemon_serial_number}" = "CHANGEME" ]; then
    sn=$(echo $mac | awk '{gsub(":", "", $0); print tolower($0)}')
    update_kdaemon_toml serial_number $sn
fi
sync;sync
