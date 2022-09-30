#!/bin/sh

. /etc/fika_manager/common.sh
. /etc/fika_manager/provision.sh library

load_kdaemon_toml

# {cmd} {ap-info json string}

fika_log debug "[$0] $@"

info="$@"
keySet="kap.boss.ap.info"

old=$(fika_redis GET ${keySet})

oldUserWallet=$(echo "$old" | jq -r .user_wallet)
oldDeviceNickname=$(echo "$old" | jq -r .device_nickname)

newUserWallet=$(echo "$info" | jq -r .user_wallet)
newDeviceNickname=$(echo "$info" | jq -r .device_nickname)

fika_redis SET "${keySet}" "${info}" 2>&1 >/dev/null
fika_redis EXPIRE ${keySet} 10 2>&1 >/dev/null
fika_log info "[$0] save ${info}/10s into ${keySet}"

provisionUpdate=false
if [ "x$kdaemon_nickname" != "x$newDeviceNickname" ]; then
    update_kdaemon_toml nickname "${newDeviceNickname}"
    provisionUpdate=true
fi
if [ "x$oldUserWallet" != "x$newUserWallet" ]; then
    update_kdaemon_toml user_wallet ${newUserWallet}
    provisionUpdate=true
fi
if [ "x$oldDeviceNickname" != "x$newDeviceNickname" ]; then
    provisionUpdate=true
fi

$provisionUpdate && provision_sync_aws
exit 0
