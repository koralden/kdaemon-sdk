#!/bin/sh

DEBUG=0

. /etc/fika_manager/hcs_honest_challenge.sh

post_challenger() {
    local response hashed json code
    local cid

    tid=$1 && shift
    cid=$1 && shift

    #fika_log debug "[post_challenger]: tid=$tid challengeId=$challengeId"

    report_boss_hcs "$cid" "$tid"
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

    if tasks=$(fika-manager boss get-hcs); then
        lastToken=$(fika_redis LINDEX ${KEY_BOSS_HCS_LIST} -1 | jq -r .hcs_token)
        [ -z "${lastToken}" -o "Xnull" = "X${lastToken}" ] && lastToken="0000000000"

        echo $tasks | jq -cr .[] | \
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
