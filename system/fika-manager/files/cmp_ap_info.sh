#!/bin/sh

. /etc/fika_manager/common.sh
. /etc/fika_manager/provision.sh library

load_kdaemon_toml

# {cmd} {ap-info json string}

fika_log debug "[$0] $@"

info=$1 && shift
APInfoKey="kap.boss.ap.info"

fika_redis SET $APInfoKey "${info}" 2>&1 >/dev/null
fika_log info "[$0] save ${info} into $APInfoKey"

newUserWallet=$(echo "$info" | jaq -r .user_wallet)
newDeviceNickname=$(echo "$info" | jaq -r .device_nickname)

provisionUpdate=false
if [ "x$kdaemon_nickname" != "x$newDeviceNickname" ]; then
    update_kdaemon_toml por.nickname str "${newDeviceNickname}"
    provisionUpdate=true
fi
if [ "x$kdaemon_user_wallet" != "x$newUserWallet" ]; then
    update_kdaemon_toml core.user_wallet str ${newUserWallet}
    provisionUpdate=true
fi

$provisionUpdate && provision_sync_aws
exit 0
