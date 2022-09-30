#!/bin/sh

DEBUG=0

. /etc/fika_manager/hcs_honest_challenge.sh

post_challenger() {
    local response challenger hashed json code
    local cid

    tid=$1 && shift
    cid=$1 && shift

    #fika_log debug "[post_challenger]: tid=$tid challengeId=$challengeId"

    challenger=$(fika_redis HGET ${KEY_BOSS_HCS_CHALLENGERS}.${tid} ${cid})
    hashed=$(echo $challenger | jq -r .hashed)

    report_boss_hcs "$cid" "$hashed" "$tid"
}

remove_expired_task() {
    local now older item cc
    local tid invalidT invalidS

    now=$(date +%s)
    for item in $(fika_redis LRANGE ${KEY_BOSS_HCS_LIST} 0 -1); do
        [ -z "$item" ] && break
        tid=$(echo $item | jq -r .hcs_token)
        invalidT=$(echo $item | jq -r .invalid_time)
        invalidS=$(fika-manager misc -s $invalidT)

        if [ $now -ge $invalidS ]; then
            for cc in $(fika_redis HKEYS ${KEY_BOSS_HCS_CHALLENGERS}.${tid}); do
                post_challenger $tid $cc
            done

            older=$(fika_redis LMOVE ${KEY_BOSS_HCS_LIST} ${KEY_BOSS_HCS_LIST}.history LEFT RIGHT)
            fika_log info "[hcs] move ${older} to ${KEY_BOSS_HCS_LIST}.history"
            if [ $(fika_redis LLEN ${KEY_BOSS_HCS_LIST}.history) -eq 128 ]; then
                tid=$(fika_redis LPOP ${KEY_BOSS_HCS_LIST}.history | jq -r .hcs_token)
                fika_redis DEL ${KEY_BOSS_HCS_CHALLENGERS}.${tid}
                fika_log warn "[hcs] drop ${tid} from ${KEY_BOSS_HCS_LIST}.history"
            fi
        else
            break
        fi
    done
}

get_main() {
    local tasks code hcs
    local lastToken hcsToken

    db_fetch

    tasks=$(curl -s -H "ACCESSTOKEN:${accessToken}" -H "ACCESSTOKEN-AP:${accesstokenAp}" -X GET "${rootUrl}/${hcsPath}?ap_wallet=${kapWallet}")
    fika_log debug "[hcs] curl -H \"ACCESSTOKEN:${accessToken}\" -H \"ACCESSTOKEN-AP:${accesstokenAp}\" ${rootUrl}/${hcsPath}?ap_wallet=${kapWallet} => ${tasks}"

    [ $DEBUG -eq 1 ] && tasks='{"hcs":[{"hcs_sid":"2022072215014100001","hcs_token":"94efde4c624ce129eab0756b52897de3","init_time":"2022-07-22T15:01:41+0800","invalid_time":"2022-07-22T16:19:41+0800"},{"hcs_sid":"2022072216012700001","hcs_token":"9f2d802c8f8854f82cc9ea9e5390c26f","init_time":"2022-07-22T16:01:27+0800","invalid_time":"2022-07-22T17:18:27+0800"}],"code":200}'

    code=$(echo $tasks | jq -r .code)
    hcs=$(echo $tasks | jq -cr .hcs[])
    if [ "X$code" = "X200" -a -n "$hcs" ]; then
        lastToken=$(fika_redis LINDEX ${KEY_BOSS_HCS_LIST} -1 | jq -r .hcs_token)
        [ -z "${lastToken}" -o "Xnull" = "X${lastToken}" ] && lastToken="0000000000"

        echo $tasks | jq -cr .hcs[] | \
            while read item; do
                hcsToken=$(echo $item | jq -r .hcs_token)
                if [ ${hcsToken} != ${lastToken} ]; then
                    fika_redis RPUSH ${KEY_BOSS_HCS_LIST} "$item"

                    if [ $(fika_redis LLEN ${KEY_BOSS_HCS_LIST}) -eq 128 ]; then
                        tid=$(fika_redis LPOP ${KEY_BOSS_HCS_LIST} | jq -r .hcs_token)
                        fika_log error "[hcs] ${KEY_BOSS_HCS_LIST} overflow(128), drop ${tid}"
                        break
                    fi
                    fika_log info "[hcs] ${item} new task in"
                    lastToken=${hcsToken}
                else
                    fika_log warn "[hcs] ${item} already in(ignore)"
                fi
            done
        true
    else
        false
    fi

    # post/sync all result to BOSS
    remove_expired_task
}

[ $# -eq 0 ] && get_main
