#!/bin/sh

DEBUG=0

my_log() {
    level=$1 && shift

    [ -e /dev/log ] && logger -s -t fika-manager -p ${level} "$@"
    echo "[fika-manager][${level}] $@"

    [ $DEBUG -eq 1 ] && echo "[fika-manager][${level}] $@" >>/tmp/factory.log
}

my_log debug "[$0] $@"

orig=$1 && shift
key=$1 && shift

. /lib/functions.sh

config_load network
#local wan_type wan_username wan_password wifi_ssid wifi_password password_overwrite proto
config_get proto wan proto dhcp
wan_type=0
[ "X$proto" = "Xpppoe" ] && wan_type=1
#wan_username=$(uci get network.wan.username)
#wan_passwrod=$(uci get network.wan.password)
config_get wan_username wan username "changeme"
config_get wan_password wan password "changeme"

config_load wireless
#wifi_ssid=$(uci get wireless.ssid0.ssid)
#wifi_password=$(uci get wireless.ssid0.key)
config_get wifi_ssid ssid0 ssid "K-Private"
config_get wifi_password ssid0 key "changeme"

password_overwrite="on"

json=$(jq -rcM --null-input \
    --argjson wan_type $wan_type \
    --arg wan_username "$wan_username" \
    --arg wan_password "$wan_password" \
    --arg wifi_ssid "$wifi_ssid" \
    --arg wifi_password "$wifi_password" \
    --arg password_overwrite "$password_overwrite" \
    '{ "wan_type": $wan_type, "wan_username": $wan_username, "wan_password": $wan_password, "wifi_ssid": $wifi_ssid, "wifi_password": $wifi_password, "password_overwrite": $password_overwrite }')

redis-cli set $key $json
