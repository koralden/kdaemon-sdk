#!/bin/sh

. /etc/fika_manager/misc.sh
. /lib/functions.sh

# TODO, data unsync if fika-ez => origin setup, sync until reboot
# maybe remove redis/cache and always call this script every time

fika_log debug "[$0] $@"

json=$1 && shift
key=$1 && shift

config_load network
#local wan_type wan_username wan_password wifi_ssid wifi_password password_overwrite proto
config_get proto wan proto dhcp
wan_type=0
[ "X$proto" = "Xpppoe" ] && wan_type=1
config_get wan_username wan username "changeme"
config_get wan_password wan password "changeme"

config_load wireless
config_get wifi_ssid ssid0 ssid "K-Private"
config_get wifi_password ssid0 key "changeme"

password_overwrite=$(echo $json | jq -r .password_overwrite)

json=$(jq -rcM --null-input \
    --argjson wan_type $wan_type \
    --arg wan_username "$wan_username" \
    --arg wan_password "$wan_password" \
    --arg wifi_ssid "$wifi_ssid" \
    --arg wifi_password "$wifi_password" \
    --arg password_overwrite $password_overwrite \
    '{ "wan_type": $wan_type, "wan_username": $wan_username, "wan_password": $wan_password, "wifi_ssid": $wifi_ssid, "wifi_password": $wifi_password, "password_overwrite": $password_overwrite }')

redis-cli set $key $json
