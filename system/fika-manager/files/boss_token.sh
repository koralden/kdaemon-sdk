#!/bin/sh

DEBUG=0

my_log() {
    level=$1 && shift

    if [ -e /dev/log ]; then
        logger -s -t fika-manager -p ${level} "$@"
    else
        echo "[fika-manager][${level}] $@"
    fi
}

get_access_token_ap() {
    local atoken=$1 && shift
    local url=$1 && shift
    local json

    json=$(curl -s -H "ACCESSTOKEN:${atoken}" -X GET ${url})
    #my_log debug "curl ap_token $json"

    code=$(echo $json | jq -r .code)
    if [ $code -eq 200 ]; then
        apToken=$(echo $json | jq -r .ap_token)
        #my_log debug "apToken as $apToken"
        echo "$apToken"
    #else
        #my_log error "NO B/OSS ACCESSTOKEN-AP because ${response}, force exit" 
        #exit 127
    fi
}

post_challenger() {
    sid=$1 && shift
    challengeId=$1 && shift

    challenger=$(redis-cli --raw HGET boss.hcs.challengers.${sid} ${challengeId})
    hashed=$(echo $challenger | jq -r .hashed)

    json=$(jq -rcM --null-input \
        --arg wallet "$challengeId" \
        --arg hashed "$hashed" \
        '{ "app_wallet": $wallet, "hashed": $hashed}')

    response=$(curl -s -H "ACCESSTOKEN:${accesstoken}" -H "ACCESSTOKEN-AP:${accesstokenAp}" -X POST -d $json "${rootUrl}/${hcsPath}?ap_wallet=${kapWallet}")
    my_log debug $response
    code=$(echo $response | jq -r .code)
    if [ $code -eq 200 ]; then
        changed=$(echo $challenger | jq -rcM --argjson send true '.send = $send')
        redis-cli HDEL boss.hcs.challengers.${sid} ${challengeId}
        my_log debug "redis-cli HDEL boss.hcs.challengers.${sid} ${challengeId}"
    else
        my_log error "POST $json ${rootUrl}/${hcsPath}?ap_wallet=${kapWallet} fail"
    fi
}

remove_expired_task() {
    now=$(date +%s)
    redis-cli lrange boss.hcs.token.list 0 -1 |
        while read item; do
            [ -z "$item" ] && break
            invalidT=$(echo $item | jq -r .invalid_time)
            invalidS=$(date -d "$(echo ${invalidT} | sed -e 's,T, ,' -e 's,+.*$,,')" +%s)
            sid=$(echo $item | jq -r .hcs_sid)

            if [ $now -ge $invalidS ]; then
                redis-cli HKEYS boss.hcs.challengers.${sid} | \
                    while read cc; do
                        post_challenger $sid $cc
                    done
                redis-cli LPOP boss.hcs.token.list
                redis-cli DEL boss.hcs.challengers.${sid}
                continue
            fi
            break
        done
}

# curl -s -H 'ACCESSTOKEN:ce18d7a0940719a00da82448b38c90b2' -X GET "https://oss-api.k36588.info/v0/ap/ap_token?ap_wallet=0x365962cd383a593975E743fD59Bbf2C1Bc141CF5"
#{"ap_token":"02ec7a905b70689d9b30c6118fd1e62f","code":200}⏎ 

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

#[ $DEBUG -eq 1 ] && redis-cli SET kap.boss.ap.token 02ec7a905b70689d9b30c6118fd1e62f
#if [ -z "$accesstokenAp" ]; then
#    accesstokenAp=$(get_access_token_ap $accesstoken "${rootUrl}/${apTokenPath}?ap_wallet=${kapWallet}")
#    redis-cli SET kap.boss.ap.token $accesstokenAp
#else
#    my_log info "api accesstoken-ap as $accesstokenAp"
#fi

[ -z "$rootUrl" -o -z "$accesstoken" -o -z "$accesstokenAp" -o -z "$kapWallet" ] && exit 127

remove_expired_task

response=$(curl -s -H "ACCESSTOKEN:${accesstoken}" -H "ACCESSTOKEN-AP:${accesstokenAp}" -X GET "${rootUrl}/${hcsPath}?ap_wallet=${kapWallet}")
[ $DEBUG -eq 1 ] && response='{"hcs":[{"hcs_sid":"2022072215014100001","hcs_token":"94efde4c624ce129eab0756b52897de3","init_time":"2022-07-22T15:01:41+0800","invalid_time":"2022-07-22T16:19:41+0800"},{"hcs_sid":"2022072216012700001","hcs_token":"9f2d802c8f8854f82cc9ea9e5390c26f","init_time":"2022-07-22T16:01:27+0800","invalid_time":"2022-07-22T17:18:27+0800"}],"code":200}'

my_log debug $response
code=$(echo $response | jq -r .code)
if [ $code -eq 200 ]; then
    #XXX add EX to purge expire token?

    lastOne=$(redis-cli lindex boss.hcs.token.list -1 | jq -r .hcs_sid)
    [ -z "${lastOne}" -o "Xnull" = "X${lastOne}" ] && lastOne=0

    echo $response | jq -cr .hcs[] | \
        while read item; do
            if [ $(echo $item | jq -r .hcs_sid) -gt ${lastOne} ]; then
                echo "=>$item<="
                redis-cli rpush boss.hcs.token.list "$item"
            else
                my_log info "item - ${item} already in"
            fi
        done

    #redis-cli SET boss.hcs.token $response
    #my_log debug redis-cli SET boss.hcs.token $response
#else
#    my_log debug redis-cli DEL boss.hcs.token
#    redis-cli DEL boss.hcs.token
fi
