#!/bin/sh

#DEBUG=1

my_log() {
    level=$1 && shift

    [ -e /dev/log ] && logger -s -t fika-manager -p ${level} "$@"
    echo "[fika-manager][${level}] $@"
}

# curl -s -H 'ACCESSTOKEN:ce18d7a0940719a00da82448b38c90b2' -X GET "https://oss-api.k36588.info/v0/ap/ap_token?ap_wallet=0x365962cd383a593975E743fD59Bbf2C1Bc141CF5"
#{"ap_token":"02ec7a905b70689d9b30c6118fd1e62f","code":200}⏎ 

appUrl=$(redis-cli --raw GET boss.app.url)
[ -z "$appUrl" ] && appUrl="https://oss-api.k36588.info"

kapWallet=$(redis-cli --raw GET kap.wallet.addr)
[ -z "$kapWallet" ] && kapWallet="0x365962cd383a593975E743fD59Bbf2C1Bc141CF5"

accesstoken=$(redis-cli --raw GET boss.accesstoken)
[ -z "$accesstoken" ] && accesstoken="ce18d7a0940719a00da82448b38c90b2"

my_log debug "appUrl: $appUrl"
my_log debug "kapWallet: $kapWallet"
my_log debug "accesstoken: $accesstoken"

accesstokenAp=$(redis-cli --raw GET boss.accesstoken.ap)
if [ -z "$accesstokenAp" ]; then
    response=$(curl -s -H "ACCESSTOKEN:${accesstoken}" \
        -X GET "${appUrl}/v0/ap/ap_token?ap_wallet=${kapWallet}")
    my_log debug "curl ap_token $response"

    code=$(echo $response | jq -r .code)
    if [ $code -eq 200 ]; then
        accesstokenAp=$(echo $response | jq -r .ap_token)
        my_log debug "accesstokenAp as $accesstokenAp"
        redis-cli SET boss.accesstoken.ap $accesstokenAp
    else
        [ $DEBUG -eq 1 ] && redis-cli SET boss.accesstoken.ap 02ec7a905b70689d9b30c6118fd1e62f
        my_log error "NO B/OSS ACCESSTOKEN-AP because ${response}, force exit" 
        exit 127
    fi
else
    my_log info "api accesstoken-ap as $accesstokenAp"
fi

response=$(curl -s -H "ACCESSTOKEN:${accesstoken}" -H "ACCESSTOKEN-AP:${accesstokenAp}" -X GET "${appUrl}/v0/ap/hcs_pair?ap_wallet=${kapWallet}")
[ $DEBUG -eq 1 ] && response='{"hsc_token":"testtoken","init_time":"2022-07-20T13:10:59+0800","invalid_time":"2022-07-20T13:16:00+0800","code":200}'
my_log debug $response
code=$(echo $response | jq -r .code)
if [ $code -eq 200 ]; then
    #XXX add EX to purge expire token?
    redis-cli SET boss.hcs.token $response
    my_log debug redis-cli SET boss.hcs.token $response
else
    my_log debug redis-cli DEL boss.hcs.token
    redis-cli DEL boss.hcs.token
fi
