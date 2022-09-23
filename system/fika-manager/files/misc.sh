#!/bin/sh

KDAEMON_TOML_PATH="/userdata/kdaemon.toml"
RULE_TOML_PATH="/etc/fika_manager/rule.toml"

fika_log() {
    level=$1 && shift

    if [ -e /dev/log ]; then
        logger -p ${level} "$@"
    else
        echo "[${level}] $@"
    fi
}

load_kdaemon_toml() {
    local conf

    conf=$KDAEMON_TOML_PATH
    [ $# -gt 0 ] && conf=$1
    eval "$(sed -e '/^\[/d' -e '/^#/d' -e '/^\s*$/d' -e 's,^,kdaemon_,g' -e 's, = ,=,g' $conf)"
}

update_kdaemon_toml() {
    key=$1
    val=$2

    str="\"$val\""
    echo $val | grep -q -E "^[0-9]+$" && str=$val
    echo $val | grep -q -i -E "(false)|(true)" && str=$val

    sed "s,^#*$key.*$,$key = $str,g" -i $KDAEMON_TOML_PATH && sync
}
