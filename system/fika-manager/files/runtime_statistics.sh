#!/bin/sh

type="DHCP"             # TODO
ipaddr="TODO"
bandwidth="TODO"

public_ssid="TODO"
public_client_num=100   # TODO 
public_rssi=40          # TODO

private_ssid="TODO"
private_client_num=1    # TODO
private_rssi=60.1       # TODO

wan=$(jaq -rc --null-input \
    --arg type "$type" \
    --arg ipaddr "$ipaddr" \
    --arg bandwidth "$bandwidth" \
    '{ "type": $type, "ipaddress": $ipaddr, "bandwidth": $bandwidth }')

wlan_public=$(jaq -rc --null-input \
    --arg ssid "$public_ssid" \
    --argjson cn "$public_client_num" \
    --argjson rssi "$public_rssi" \
    '{ "ssid": $ssid, "client-number": $cn, "rssi": $rssi }')

wlan_private=$(jaq -rc --null-input \
    --arg ssid "$private_ssid" \
    --argjson cn "$private_client_num" \
    --argjson rssi "$private_rssi" \
    '{ "ssid": $ssid, "client-number": $cn, "rssi": $rssi }')

wlan=$(jaq -rc --null-input \
    --argjson public "$wlan_public" \
    --argjson private "$wlan_private" \
    '{ "public": $public, "private": $private }')

jaq -rc --null-input \
    --argjson wan "$wan" \
    --argjson wireless "$wlan" \
    '{ "wan": $wan, "wireless": $wireless }'
