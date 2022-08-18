#!/bin/sh

[ -z "$docdir" ] && docdir="/etc/fika_manager"

#[ -e /dev/log ] && logger -s -t fika-manager -p debug "[$0] docdir=$docdir"

sdk=$(fika-manager -V | awk '{print $2}')
sdk=${sdk:-0.0.0}
wallet=$(redis-cli get kap.core | jq -r .wallet_address)
nickname=$(redis-cli get kap.por.config | jq -r .nickname)
#XXX, jq response *null* if key nonexist

jq -rcM --null-input \
    --arg sdk "$sdk" \
    --arg wallet "$wallet" \
    --arg nickname "$nickname" \
    '{ "sdk-version": $sdk, "ap-wallet-address": $wallet, "nickname": $nickname }'
