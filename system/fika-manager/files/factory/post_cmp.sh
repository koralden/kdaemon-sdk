#!/bin/sh

. /etc/fika_manager/misc.sh
load_kdaemon_toml

format_thingname() {
    eval "$(awk '/thing_prefix/ {print "thingPrefix="$3}' $RULE_TOML_PATH)"
    thing="${thingPrefix}_$(echo $kdaemon_mac_address | awk '{gsub(":", "", $0); print tolower($0)}')"
    sed "s,^.*thing.*$,thing = \"$thing\"," -i $KDAEMON_TOML_PATH
    update_kdaemon_toml thing "$thing"
}

[ -z "${kdaemon_thing}" -o "${kdaemon_thing}" = "CHANGEME" ] && format_thingname
