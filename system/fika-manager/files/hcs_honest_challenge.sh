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

# curl -s -H 'ACCESSTOKEN:ce18d7a0940719a00da82448b38c90b2' -X GET "https://oss-api.k36588.info/v0/ap/ap_token?ap_wallet=0x365962cd383a593975E743fD59Bbf2C1Bc141CF5"
#{"ap_token":"02ec7a905b70689d9b30c6118fd1e62f","code":200}⏎ 

challengeId=$1 && shift

kap_core=$(redis-cli --raw GET kap.core)
kap_boss=$(redis-cli --raw GET kap.boss)

rootUrl=$(echo $kap_boss | jq -r .root_url)
accesstoken=$(echo $kap_boss | jq -r .access_token)
apTokenPath=$(echo $kap_boss | jq -r .ap_token_path)
hcsPath=$(echo $kap_boss | jq -r .hcs_path)
kapWallet=$(echo $kap_core | jq -r .wallet_address)
accesstokenAp=$(redis-cli --raw GET kap.boss.ap.token)

my_log debug "challengeId: $challengeId"
my_log debug "appUrl: $rootUrl"
my_log debug "kapWallet: $kapWallet"
my_log debug "accesstoken: $accesstoken"
my_log debug "accesstokenAp: $accesstokenAp"

[ -z "$rootUrl" -o -z "$accesstoken" -o -z "$accesstokenAp" -o -z "$kapWallet" ] && exit 127

nowOne=$(redis-cli LINDEX boss.hcs.token.list 0 | jq -r .hcs_sid)
[ -z "${nowOne}" -o "Xnull" = "X${nowOne}" ] \
    && my_log error "not task for ${challengeId}" \
    && exit 127

challenger=$(redis-cli --raw HGET boss.hcs.challengers.${nowOne} ${challengeId)
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
    redis-cli HSET boss.hcs.challengers.${nowOne} ${challengeId} ${changed}
    my_log debug "redis-cli HSET boss.hcs.challengers.${nowOne} ${challengeId} ${changed}"
else
    my_log error "POST $json ${rootUrl}/${hcsPath}?ap_wallet=${kapWallet} fail"
fi
