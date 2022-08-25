#!/bin/sh

. /etc/fika_manager/misc.sh

DEBUG=0

KEY_BOSS_HCS_CHALLENGERS="boss.hcs.challengers"
KEY_BOSS_HCS_LIST="boss.hcs.token.list"

kapWallet=""
accesstokenAp=""
rootUrl=""
accesstoken=""
apTokenPath=""
hcsPath=""
apHcsPath=""
apInfoPath=""

db_fetch() {
    local kap_core kap_boss

    kap_core=$(redis-cli --raw GET kap.core)
    kap_boss=$(redis-cli --raw GET kap.boss)

    rootUrl=$(echo $kap_boss | jq -r .root_url)
    accesstoken=$(echo $kap_boss | jq -r .access_token)
    apTokenPath=$(echo $kap_boss | jq -r .ap_token_path)
    hcsPath=$(echo $kap_boss | jq -r .hcs_path)
    apHcsPath=$(echo $kap_boss | jq -r .ap_hcs_path)
    kapWallet=$(echo $kap_core | jq -r .wallet_address)
    accesstokenAp=$(redis-cli --raw GET kap.boss.ap.token)
    apHcsPath=$(echo $kap_boss | jq -r .ap_info_path)

    apTokenPath=${apTokenPath:-"v0/ap/ap_token"}
    hcsPath=${hcsPath:-"v0/hcs/pair"}
    apHcsPath=${apHcsPath:-"v0/ap/hcs"}
    apInfoPath=${apInfoPath:-"v0/ap/info"}

    fika_log debug "appUrl: $rootUrl kapWallet: $kapWallet accesstoken: $accesstoken accesstokenAp: $accesstokenAp"

    [ -z "$rootUrl" -o -z "$accesstoken" -o -z "$accesstokenAp" -o -z "$kapWallet" ] && \
        fika_log error "database rootUrl/accesstoken/accesstokenAp/kapWallet=${rootUrl}/${accesstoken}/${accesstokenAp}/${kapWallet} invalid" && \
        exit 127

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

    response=$(curl -s -H "ACCESSTOKEN:${accesstoken}" -H "ACCESSTOKEN-AP:${accesstokenAp}" -X POST -d $json "${rootUrl}/${apHcsPath}?ap_wallet=${kapWallet}")
    code=$(echo $response | jq -r .code)
    if [ "X$code" = "X200" ]; then
        changed=$(echo $challenger | jq -rcM --argjson sent true '.sent = $sent')
        redis-cli HSET ${KEY_BOSS_HCS_CHALLENGERS}.${tid} ${cid} ${changed}
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

    response=$(curl -s -H "ACCESSTOKEN:${accesstoken}" -H "ACCESSTOKEN-AP:${accesstokenAp}" -H 'Content-Type: text/plain' -X POST --data-raw $raw "${rootUrl}/${apHcsPath}")
    code=$(echo $response | jq -r .code)
    if [ "X$code" = "X200" ]; then
        changed=$(echo $challenger | jq -rcM --argjson sent true '.sent = $sent')
        redis-cli HSET ${KEY_BOSS_HCS_CHALLENGERS}.${tid} ${cid} ${changed}
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

    challenger=$(redis-cli --raw HGET ${KEY_BOSS_HCS_CHALLENGERS}.${tid} ${cid})
    if [ -z "$challenger" ]; then
        fika_log debug "No any challengers in this task-${tid}"
        exit 0
    fi

    hashed=$(echo $challenger | jq -r .hashed)

    db_fetch && report_boss_hcs "$cid" "$hashed" "$tid"
}

[ $# -gt 0 ] && post_main $@
