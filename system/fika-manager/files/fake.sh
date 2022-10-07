#!/bin/sh

. /etc/fika_manager/misc.sh

RootFake="/root/fake"
RootBoss="/root/boss"

boss_ap_info() {
    local info

    conf=$1

    if info=$(fika-manager boss -c $RootFake/$conf/kdaemon.toml get-ap-info) ; then
        echo "user_wallet = \"$(echo $info | jq -r .user_wallet)\"" >$RootBoss/$conf
        echo "nickname = \"$(echo $info | jq -r .device_nickname)\"" >>$RootBoss/$conf
        sync;sync
        return 0
    else
        return 127
    fi
}

publish_provision() {
    conf=$1
    load_kdaemon_toml $RootFake/$conf/kdaemon.toml
    load_kdaemon_toml $RootBoss/$conf

    sdk=$(fika-manager -V | awk '{print $2}')
    sdk=${sdk:-0.0.0}
    wallet="${kdaemon_wallet_address}"
    nickname="${kdaemon_nickname}"
    owner="${kdaemon_user_wallet}"

    msg=$(jq -rcM --null-input \
        --arg sdk "$sdk" \
        --arg wallet "$wallet" \
        --arg nickname "$nickname" \
        --arg owner "$owner" \
        '{"state":{"reported":{ "sdk-version": $sdk, "ap-wallet-address": $wallet, "nickname": $nickname, "owner": $owner }},"clientToken": "11111"}')

    fika_redis publish kap/aws/raw/things/${kdaemon_thing}/shadow/name/provision/update "$msg"
}

publish_heartbeat() {
    conf=$1
    load_kdaemon_toml $RootFake/$conf/kdaemon.toml

    latency=50
    uptime=$(cat /proc/uptime  | awk '{print $1}')

    systime=$(fika-manager misc --rfc3339)

    msg=$(jq -rcM --null-input \
        --argjson uptime "$uptime" \
        --argjson latency "$latency" \
        --arg systime "$systime" \
        '{"state":{"reported":{"up-time": $uptime, "latency": $latency, "system-time": $systime}},"clientToken": "11111"}')
    fika_redis publish kap/aws/raw/things/${kdaemon_thing}/shadow/name/heartbeat/update "$msg"
}

test_loop() {
    for conf in $(ls /root/fake); do
        [ -d $RootBoss ] || mkdir /root/boss
        if [ -e $RootBoss/$conf ]; then
            publish_heartbeat $conf
        else
            boss_ap_info $conf
            publish_provision $conf
        fi
    done
}

if [ $# -eq 0 ]; then
    test_loop
fi
