#!/bin/sh

DEBUG=0

source /etc/fika_manager/hcs_honest_challenge.sh

post_challenger() {
    local response challenger hashed json code
    local cid

    sid=$1 && shift
    cid=$1 && shift

    #my_log debug "[post_challenger]: sid=$sid challengeId=$challengeId"

    challenger=$(redis-cli --raw HGET boss.hcs.challengers.${sid} ${cid})
    hashed=$(echo $challenger | jq -r .hashed)

    report_boss_hcs "$cid" "$hashed" "$sid"
}

remove_expired_task() {
    now=$(date +%s)
    for item in $(redis-cli LRANGE boss.hcs.token.list 0 -1); do
        #my_log debug "[remove_expired_task]: item=$item"
        [ -z "$item" ] && break
        invalidT=$(echo $item | jq -r .invalid_time)
        invalidS=$(date -d "$(echo ${invalidT} | sed -e 's,T, ,' -e 's,+.*$,,')" +%s)
        sid=$(echo $item | jq -r .hcs_sid)

        #my_log debug "[remove_expired_task]: invalidT=$invalidT invalidS=$invalidS sid=$sid vs now=$now"

        if [ $now -ge $invalidS ]; then
            for cc in $(redis-cli HKEYS boss.hcs.challengers.${sid}); do
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

#[ $DEBUG -eq 1 ] && redis-cli SET kap.boss.ap.token 02ec7a905b70689d9b30c6118fd1e62f
#if [ -z "$accesstokenAp" ]; then
#    accesstokenAp=$(get_boss_ap_token $accesstoken "${rootUrl}/${apTokenPath}?ap_wallet=${kapWallet}")
#    redis-cli SET kap.boss.ap.token $accesstokenAp
#else
#    my_log info "api accesstoken-ap as $accesstokenAp"
#fi

get_main() {
    local tasks code hcs hashOne

    db_fetch

    remove_expired_task

    tasks=$(curl -s -H "ACCESSTOKEN:${accesstoken}" -H "ACCESSTOKEN-AP:${accesstokenAp}" -X GET "${rootUrl}/${hcsPath}?ap_wallet=${kapWallet}")
    [ $DEBUG -eq 1 ] && tasks='{"hcs":[{"hcs_sid":"2022072215014100001","hcs_token":"94efde4c624ce129eab0756b52897de3","init_time":"2022-07-22T15:01:41+0800","invalid_time":"2022-07-22T16:19:41+0800"},{"hcs_sid":"2022072216012700001","hcs_token":"9f2d802c8f8854f82cc9ea9e5390c26f","init_time":"2022-07-22T16:01:27+0800","invalid_time":"2022-07-22T17:18:27+0800"}],"code":200}'

    code=$(echo $tasks | jq -r .code)
    hcs=$(echo $tasks | jq -cr .hcs[])
    if [ "X$code" = "X200" -a -n "$hcs" ]; then
        #XXX add EX to purge expire token?

        lastOne=$(redis-cli LINDEX boss.hcs.token.list -1 | jq -r .hcs_sid)
        [ -z "${lastOne}" -o "Xnull" = "X${lastOne}" ] && lastOne=0

        echo $tasks | jq -cr .hcs[] | \
            while read item; do
                if [ $(echo $item | jq -r .hcs_sid) -gt ${lastOne} ]; then
                    redis-cli RPUSH boss.hcs.token.list "$item"
                else
                    my_log info "item - ${item} already in"
                fi
            done

        #redis-cli SET boss.hcs.token $tasks
        #my_log debug redis-cli SET boss.hcs.token $tasks
        #else
        #    my_log debug redis-cli DEL boss.hcs.token
        #    redis-cli DEL boss.hcs.token
        true
    else
        false
    fi
}

get_main
