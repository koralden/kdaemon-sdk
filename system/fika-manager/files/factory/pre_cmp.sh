#!/bin/sh

. /etc/fika_manager/misc.sh

[ -e /etc/fika_iot_gateway/config.yaml ] || {
    fika_log debug "[$0] cp /etc/fika_iot_gateway/config.yaml.sample /etc/fika_iot_gateway/config.yaml"

    cp /etc/fika_iot_gateway/config.yaml.sample /etc/fika_iot_gateway/config.yaml
    sync;sync
}
