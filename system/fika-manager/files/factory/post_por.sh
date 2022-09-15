#!/bin/sh

. /etc/fika_manager/misc.sh

load_kdaemon_toml

default_nickname() {
    mac=$(echo ${kdaemon_mac_address} | awk 'BEGIN{FS=":"};{print toupper($4$5$6)}')
    sed "s,^.*nickname.*$,nickname = \"K-AP-$mac\"," -i $KDAEMON_TOML_PATH
}

[ -z "${kdaemon_nickname}" -o "${kdaemon_nickname}" = "CHANGEME" ] && default_nickname
