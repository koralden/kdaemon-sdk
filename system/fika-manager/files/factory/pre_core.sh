#!/bin/sh

. /etc/fika_manager/misc.sh

[ -e /etc/fika-redis.conf ] || {
    fika_log debug "[$0] cp /etc/fika-redis.conf.sample /etc/fika-redis.conf"

    cp /etc/fika-redis.conf.sample /etc/fika-redis.conf
}

[ -e /etc/fika_manager/rule.toml ] || {
    fika_log debug "[$0] cp /etc/fika_manager/rule.toml.sample /etc/fika_manager/rule.toml"

    cp /etc/fika_manager/rule.toml.sample /etc/fika_manager/rule.toml
}

[ -e $KDAEMON_TOML_PATH ] || {
    [ -d $(dirname $KDAEMON_TOML_PATH) ] || mkdir -p $(dirname $KDAEMON_TOML_PATH)
    if [ -e /userdata/factory.toml ]; then
        fika_log debug "[$0] cp /userdata/factory.toml $KDAEMON_TOML_PATH"
        cp /userdata/factory.toml $KDAEMON_TOML_PATH
    else
        fika_log debug "[$0] cp /etc/fika_manager/kdaemon.toml.sample $KDAEMON_TOML_PATH"
        cp /etc/fika_manager/kdaemon.toml.sample $KDAEMON_TOML_PATH
    fi
}
sync;sync
