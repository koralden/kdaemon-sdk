#!/bin/sh

. /etc/fika_manager/misc.sh
. /lib/functions.sh

load_kdaemon_toml

# TODO, data unsync if fika-ez => origin setup, sync until reboot
# maybe remove redis/cache and always call this script every time

fika_log debug "[$0] $@"

config_load network
#local wan_type wan_username wan_password wifi_ssid wifi_password password_overwrite proto
config_get proto wan proto dhcp
wan_type=0
[ "X$proto" = "Xpppoe" ] && wan_type=1
config_get wan_username wan username "CHANGEME"
config_get wan_password wan password "CHANGEME"

config_load wireless
config_get wifi_ssid ssid0 ssid "K-Private"
config_get wifi_password ssid0 key "changeme"

sed -e "s,^[\t #]*wan_username.*$,wan_username = \"$wan_username\"," \
    -e "s,^[\t #]*wan_password.*$,wan_password = \"$wan_password\"," \
    -e "s,^[\t #]*wifi_ssid.*$,wifi_ssid = \"$wifi_ssid\"," \
    -e "s,^[\t #]*wifi_password.*$,wifi_password = \"$wifi_password\"," \
    -i $KDAEMON_TOML_PATH
