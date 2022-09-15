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
        fika_log error "database rootUrl/accessToken/accesstokenAp/kapWallet=${rootUrl}/${accessToken}/${accesstokenAp}/${kapWallet} invalid"
        exit 127
    else
        fika_log debug "appUrl: $rootUrl kapWallet: $kapWallet accessToken: $accessToken accesstokenAp: $accesstokenAp"
    fi

    true
}

report_boss_hcs_json() {
    local cid hashed changed json tid

    cid=$1 && shift
    hashed=$1 && shift
    tid=$1 && shift

    json=$(jq -rcM --null-input \
        --arg wallet "$cid" \
        --arg hashed "$hashed" \
        '{ "app_wallet": $wallet, "hashed": $hashed}')

    response=$(curl -s -H "ACCESSTOKEN:${accessToken}" -H "ACCESSTOKEN-AP:${accesstokenAp}" -X POST -d $json "${rootUrl}/${apHcsPath}?ap_wallet=${kapWallet}")
    code=$(echo $response | jq -r .code)
    if [ "X$code" = "X200" ]; then
        changed=$(echo $challenger | jq -rcM --argjson sent true '.sent = $sent')
        redis-cli HSET ${KEY_BOSS_HCS_CHALLENGERS}.${tid} ${cid} "${changed}"
        fika_log debug "redis-cli HSET ${KEY_BOSS_HCS_CHALLENGERS}.${tid} ${cid} ${changed}"
        true
    else
        fika_log error "POST $json ${rootUrl}/${apHcsPath}?ap_wallet=${kapWallet} fail"
        false
    fi
}

report_boss_hcs() {
    local cid hashed changed json tid

    cid=$1 && shift
    hashed=$1 && shift
    tid=$1 && shift

    [ "X$(redis-cli HGET ${KEY_BOSS_HCS_CHALLENGERS}.${tid} ${cid} | jq .sent)" = "Xtrue" ] && return

    raw="hcs_token=${tid}&ap_wallet=${kapWallet}&hash=${hashed}"

    response=$(curl -s -H "ACCESSTOKEN:${accessToken}" -H "ACCESSTOKEN-AP:${accesstokenAp}" -H 'Content-Type: text/plain' -X POST --data-raw $raw "${rootUrl}/${apHcsPath}")
    code=$(echo $response | jq -r .code)
    if [ "X$code" = "X200" ]; then
        changed=$(echo $challenger | jq -rcM --argjson sent true '.sent = $sent')
        redis-cli HSET ${KEY_BOSS_HCS_CHALLENGERS}.${tid} ${cid} "${changed}"
        fika_log debug "redis-cli HSET ${KEY_BOSS_HCS_CHALLENGERS}.${tid} ${cid} ${changed}"
        true
    else
        fika_log error "POST $raw ${rootUrl}/${apHcsPath} fail"
        false
    fi
}

# curl -s -H 'ACCESSTOKEN:ce18d7a0940719a00da82448b38c90b2' -X GET "https://oss-api.k36588.info/v0/ap/ap_token?ap_wallet=0x365962cd383a593975E743fD59Bbf2C1Bc141CF5"
#{"ap_token":"02ec7a905b70689d9b30c6118fd1e62f","code":200}⏎ 

post_main() {
    local cid tid

    cid=$1 && shift

    tid=$(redis-cli LINDEX ${KEY_BOSS_HCS_LIST} 0 | jq -r .hcs_token)
    [ -z "${tid}" -o "Xnull" = "X${tid}" ] \
        && fika_log error "not task for ${cid}" \
        && exit 127

    challenger=$(redis-cli --raw HGET "${KEY_BOSS_HCS_CHALLENGERS}.${tid}" "${cid}")
    if [ -z "$challenger" ]; then
        fika_log debug "No any challengers in this task-${tid}"
        exit 0
    fi

    hashed=$(echo $challenger | jq -r .hashed)

    db_fetch && report_boss_hcs "$cid" "$hashed" "$tid"
}

[ $# -gt 0 ] && post_main $@
