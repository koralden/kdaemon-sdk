#!/bin/sh

DEBUG=0

rootUrl=""
accesstoken=""
apTokenPath=""
hcsPath=""
kapWallet=""
accesstokenAp=""

my_log() {
    level=$1 && shift

    if [ -e /dev/log ]; then
        logger -s -t hcs-honest-challenge -p ${level} "$@"
    else
        echo "[hcs-honest-challenge][${level}] $@"
    fi
}

db_fetch() {
    local kap_core kap_boss

    kap_core=$(redis-cli --raw GET kap.core)
    kap_boss=$(redis-cli --raw GET kap.boss)

    rootUrl=$(echo $kap_boss | jq -r .root_url)
    accesstoken=$(echo $kap_boss | jq -r .access_token)
    apTokenPath=$(echo $kap_boss | jq -r .ap_token_path)
    hcsPath=$(echo $kap_boss | jq -r .hcs_path)
    kapWallet=$(echo $kap_core | jq -r .wallet_address)
    accesstokenAp=$(redis-cli --raw GET kap.boss.ap.token)

    my_log debug "appUrl: $rootUrl"
    my_log debug "kapWallet: $kapWallet"
    my_log debug "accesstoken: $accesstoken"
    my_log debug "accesstokenAp: $accesstokenAp"

    [ -z "$rootUrl" -o -z "$accesstoken" -o -z "$accesstokenAp" -o -z "$kapWallet" ] && \
        my_log error "database rootUrl/accesstoken/accesstokenAp/kapWallet=${rootUrl}/${accesstoken}/${accesstokenAp}/${kapWallet} invalid" && \
        exit 127

    true
}

report_boss_hcs() {
    local cid hashed changed json tid

    cid=$1 && shift
    hashed=$1 && shift
    tid=$1 && shift

    json=$(jq -rcM --null-input \
        --arg wallet "$cid" \
        --arg hashed "$hashed" \
        '{ "app_wallet": $wallet, "hashed": $hashed}')

    response=$(curl -s -H "ACCESSTOKEN:${accesstoken}" -H "ACCESSTOKEN-AP:${accesstokenAp}" -X POST -d $json "${rootUrl}/${hcsPath}?ap_wallet=${kapWallet}")
    code=$(echo $response | jq -r .code)
    if [ "X$code" = "X200" ]; then
        changed=$(echo $challenger | jq -rcM --argjson send true '.send = $send')
        redis-cli HSET boss.hcs.challengers.${tid} ${cid} ${changed}
        my_log debug "redis-cli HSET boss.hcs.challengers.${tid} ${cid} ${changed}"
        true
    else
        my_log error "POST $json ${rootUrl}/${hcsPath}?ap_wallet=${kapWallet} fail"
        false
    fi
}

# curl -s -H 'ACCESSTOKEN:ce18d7a0940719a00da82448b38c90b2' -X GET "https://oss-api.k36588.info/v0/ap/ap_token?ap_wallet=0x365962cd383a593975E743fD59Bbf2C1Bc141CF5"
#{"ap_token":"02ec7a905b70689d9b30c6118fd1e62f","code":200}⏎ 

post_main() {
    local cid tid

    cid=$1 && shift

    tid=$(redis-cli LINDEX boss.hcs.token.list 0 | jq -r .hcs_sid)
    [ -z "${tid}" -o "Xnull" = "X${tid}" ] \
        && my_log error "not task for ${cid}" \
        && exit 127

    challenger=$(redis-cli --raw HGET boss.hcs.challengers.${tid} ${cid})
    if [ -z "$challenger" ]; then
        my_log debug "No any challengers in this task-${tid}"
        exit 0
    fi

    hashed=$(echo $challenger | jq -r .hashed)

    db_fetch && report_boss_hcs "$cid" "$hashed" "$tid"
}

[ $# -gt 0 ] && post_main $@
