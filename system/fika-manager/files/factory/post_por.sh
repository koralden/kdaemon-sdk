#!/bin/sh

. /etc/fika_manager/misc.sh

load_kdaemon_toml

default_nickname() {
    mac=$(echo ${kdaemon_mac_address} | awk 'BEGIN{FS=":"};{print toupper($4$5$6)}')
    update_kdaemon_toml nickname "K-AP-$mac"
}

[ -z "${kdaemon_nickname}" -o "${kdaemon_nickname}" = "CHANGEME" ] && default_nickname
