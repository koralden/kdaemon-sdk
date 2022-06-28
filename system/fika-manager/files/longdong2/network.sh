#!/bin/sh

wan_pppoe() {
    echo "longdong2 wan-pppoe $@"
}

wan_dhcp() {
    echo "longdong2 wan-dhcp $@"
}

wan_wwan() {
    echo "longdong2 wan-wwan $@"
}

wlan_guest() {
    echo "longdong2 wlan-guest $@"
}

wlan_private() {
    echo "longdong2 wlan-private $@"
}
