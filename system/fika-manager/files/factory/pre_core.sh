#!/bin/sh

. /etc/fika_manager/misc.sh

[ -e /etc/fika-redis.conf ] || {
    fika_log debug "[$0] cp /etc/fika-redis.conf.sample /etc/fika-redis.conf"

    cp /etc/fika-redis.conf.sample /etc/fika-redis.conf
    sync;sync
}

[ -e /etc/fika_iot_gateway/config.yaml ] || {
    fika_log debug "[$0] cp /etc/fika_iot_gateway/config.yaml.sample /etc/fika_iot_gateway/config.yaml"

    cp /etc/fika_iot_gateway/config.yaml.sample /etc/fika_iot_gateway/config.yaml
    sync;sync
}

[ -e /etc/fika_manager/config.toml ] || {
    fika_log debug "[$0] cp /etc/fika_manager/config.toml.sample /etc/fika_manager/config.toml"

    cp /etc/fika_manager/config.toml.sample /etc/fika_manager/config.toml
    sync;sync
}
