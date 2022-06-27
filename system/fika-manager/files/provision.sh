#!/bin/sh

[ -z docdir ] && docdir="/etc/fika"
sdk="\"unknown\""
wallet="unknown"

logger -s -t fika-manager -p debug "[$0] docdir=$docdir"

[ -e ${docdir}/config.toml ] && sdk=$(awk '/^version/ {print $3}' ${docdir}/config.toml)
[ -e ${docdir}/wallet.pub ] && sdk=$(cat ${docdir}/wallet.pub)

jq -rcM --null-input \
    --argjson sdk "$sdk" \
    --arg wallet "$wallet" \
    '{ "sdk-version": $sdk, "ap-wallet-address": $wallet }'
