#!/bin/sh

latency=$(ping 8.8.8.8 -c3 -q | awk -F'/' '/^round-trip/ {print $4} /^rtt/ {print $5}')
uptime=$(cat /proc/uptime  | awk '{print $1}')

# random delay  0~5 seconds
sleep $(awk -F'-' '{print strtonum(sprintf("0x%s", $2)) / 10000}' /proc/sys/kernel/random/uuid)

jq -rcM --null-input \
    --argjson uptime "$uptime" \
    --argjson latency "$latency" \
    '{ "up-time": $uptime, "latency": $latency }'
