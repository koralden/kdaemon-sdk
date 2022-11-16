#!/bin/sh

. /etc/fika_manager/misc.sh
load_kdaemon_toml

DEBUG=0

KEY_BOSS_HCS_CHALLENGERS="boss.hcs.challengers"
KEY_BOSS_HCS_LIST="boss.hcs.token.list"

kapWallet=""
accesstokenAp=""
rootUrl=""
accessToken=""
apTokenPath=""
hcsPath=""
apHcsPath=""
apInfoPath=""

db_fetch() {
    rootUrl="${kdaemon_root_url}"
    accessToken="${kdaemon_access_token}"
    apTokenPath="${kdaemon_ap_token_path}"
    hcsPath="${kdaemon_hcs_path}"
    apHcsPath="${kdaemon_ap_hcs_path}"
    kapWallet="${kdaemon_wallet_address}"
    accesstokenAp="${kdaemon_ap_access_token}"
    apInfoPath="${kdaemon_ap_info_path}"

    [ -z "$apTokenPath" -o "$apTokenPath" = "null" ] && apTokenPath="v0/ap/ap_token"
    [ -z "$hcsPath" -o "$hcsPath" = "null" ] && hcsPath="v0/hcs/pair"
    [ -z "$apHcsPath" -o "$apHcsPath" = "null" ] && apHcsPath="v0/ap/hcs"
    [ -z "$apInfoPath" -o "$apInfoPath" = "null" ] && apInfoPath="v0/ap/info"

    if [ -z "$rootUrl" -o -z "$accessToken" -o -z "$accesstokenAp" -o -z "$kapWallet" ]; then
        fika_log error "[hcs] boss config - ${rootUrl}/${accessToken}/${accesstokenAp}/${kapWallet} invalid"
        exit 127
    fi

    true
}

report_boss_hcs() {
    local cid hashed changed json tid

    cid=$1 && shift
    tid=$1 && shift

    challenger=$(fika_redis HGET "${KEY_BOSS_HCS_CHALLENGERS}.${tid}" "${cid}")
    if [ -z "$challenger" ]; then
        fika_log debug "[hcs] No any challengers in this task-${tid}"
        return
    fi

    [ "X$(echo $challenger | jaq .sent)" = "Xtrue" ] && return

    hashed=$(echo $challenger | jaq -r .hashed)

    json=$(jaq -rc --null-input \
        --arg wallet "${kdaemon_wallet_address}" \
        --arg hash "$hashed" \
        --arg token "$tid" \
        '{ "ap_wallet": $wallet,"hash":$hash,"hcs_token":$token}')

    if fika-manager boss post-ap-hcs "${json}"; then
        changed=$(echo $challenger | jaq -rc --argjson sent true '.sent = $sent')
        fika_redis HSET ${KEY_BOSS_HCS_CHALLENGERS}.${tid} ${cid} "${changed}"
        true
    else
        fika_log error "[hcs] POST $raw ${rootUrl}/${apHcsPath} fail"
        false
    fi
}

post_main() {
    local cid tid

    cid=$1 && shift

    tid=$(fika_redis LINDEX ${KEY_BOSS_HCS_LIST} 0 | jaq -r .hcs_token)
    [ -z "${tid}" -o "Xnull" = "X${tid}" ] \
        && fika_log error "[hcs] not task for ${cid}" \
        && exit 127

    report_boss_hcs "$cid" "$tid"
}

[ $# -gt 0 ] && post_main $@
