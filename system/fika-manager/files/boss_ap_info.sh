#!/bin/sh

. /etc/fika_manager/common.sh
. /etc/fika_manager/provision.sh library

# {cmd} {ap-info json string}

fika_log debug "[$0] $@"

info="$@"
keySet="kap.boss.ap.info"

old=$(redis-cli --raw GET ${keySet})

oldUserWallet=$(echo "$old" | jq -r .user_wallet)
oldDeviceNickname=$(echo "$old" | jq -r .device_nickname)
origPorConfig=$(redis-cli --raw GET kap.por.config)
origPorNickname=$(echo "$origPorConfig" | jq -r .nickname)

newUserWallet=$(echo "$info" | jq -r .user_wallet)
newDeviceNickname=$(echo "$info" | jq -r .device_nickname)

redis-cli SET "${keySet}" "${info}" 2>&1 >/dev/null
redis-cli EXPIRE ${keySet} 10 2>&1 >/dev/null
fika_log info "[$0] save ${info}/10s into ${keySet}"

if [ "x$origPorNickname" != "x$newDeviceNickname" ]; then
    newPorConfig=$(echo "$origPorConfig" | jq ".nickname = \"$newDeviceNickname\"")
    redis-cli SET kap.por.config "$newPorConfig" 2>&1 >/dev/null
    provision_sync_aws
elif [ "x$oldUserWallet" != "x$newUserWallet" ]; then
    provision_sync_aws
elif [ "x$oldDeviceNickname" != "x$newDeviceNickname" ]; then
    provision_sync_aws
fi
