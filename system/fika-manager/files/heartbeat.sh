#!/bin/sh

# random delay  0~5 seconds
#sleep $(awk -F'-' '{print strtonum(sprintf("0x%s", $2)) / 10000}' /proc/sys/kernel/random/uuid)
num=1$(awk -F'-' '{print $2}' /proc/sys/kernel/random/uuid | tr -dc '0-9')
sleep $(expr $num % 10)

endpoint=$(redis-cli get kap.cmp | jq -r .endpoint)
[ -z "$endpoint" -o "$endpoint" = "null" ] && endpoint="www.google.com"

latency=$(ping ${endpoint} -c3 -q | awk -F'/' '/^round-trip/ {print $4} /^rtt/ {print $5}')
uptime=$(cat /proc/uptime  | awk '{print $1}')

systime=$(fika-manager misc --rfc3339)

jq -rcM --null-input \
    --argjson uptime "$uptime" \
    --argjson latency "$latency" \
    --arg systime "$systime" \
    '{ "up-time": $uptime, "latency": $latency, "system-time": $systime }'
