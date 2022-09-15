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
    eval "$(sed -e '/^\[/d' -e '/^#/d' -e '/^\s*$/d' -e 's,^,kdaemon_,g' -e 's, = ,=,g' $KDAEMON_TOML_PATH)"
}
