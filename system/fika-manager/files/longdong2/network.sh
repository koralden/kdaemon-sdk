#!/bin/sh

wan_pppoe() {
    echo "longdong2 wan-pppoe $@"

    username=$1 && shift
    password=$1 && shift
    ifname=$(uci get network.wan.ifname)

    #uci set network.wan.proto=pppoe
    #uci set network.wan.username="$username"
    #uci set network.wan.password="$password"
    #uci set network.wan._orig_bridge=false
    #uci set network.wan._orig_ifname=$ifname

    uci batch << EOI
set network.wan.proto=pppoe
set network.wan.username="$username"
set network.wan.password="$password"
set network.wan._orig_bridge=false
set network.wan._orig_ifname=$ifname
EOI
    uci commit network
}

wan_dhcp() {
    echo "longdong2 wan-dhcp $@"
    uci set network.wan.proto=dhcp
    uci commit network
}

wan_wwan() {
    echo "longdong2 wan-wwan $@"
}

wlan_guest_on() {
    echo "longdong2 wlan-guest $@"

    uci batch << EOI
set network.guest=interface
set network.guest.type=bridge
set network.guest.proto=static
set network.guest.ipaddr=192.168.168.1
set network.guest.netmask=255.255.255.0
set network.guest.force_link=1
set network.guest.multicast_querier=0
set network.guest.igmp_snooping=0
set network.guest.ieee1905managed=1

set wireless.guest1=wifi-iface
set wireless.guest1.device=wifi0
set wireless.guest1.network=guest
set wireless.guest1.mode=ap
set wireless.guest1.ssid=K-public
set wireless.guest1.encryption=none

set wireless.guest2=wifi-iface
set wireless.guest2.device=wifi1
set wireless.guest2.network=guest
set wireless.guest2.mode=ap
set wireless.guest2.ssid=K-public
set wireless.guest2.encryption=none

set dhcp.guest=dhcp
set dhcp.guest.interface=guest
set dhcp.guest.start=100
set dhcp.guest.limit=150
set dhcp.guest.leasetime=12h
set dhcp.guest.force=1
set dhcp.guest.dhcpv6=server
set dhcp.guest.ra=server
EOI

    zcfg=$(uci add firewall zone)
    fcfg=$(uci add firewall forwarding)
    uci batch << EOI
set firewall.$zcfg.name=guest
set firewall.$zcfg.network=guest
set firewall.$zcfg.input=ACCEPT
set firewall.$zcfg.output=ACCEPT
set firewall.$zcfg.forward=ACCEPT

set firewall.$fcfg.src=guest
set firewall.$fcfg.dest=wan
EOI
    uci commit

    #XXX client not get ip-address from dhcp pool
    /etc/init.d/firewall reload
    /etc/init.d/network reload
}

wlan_guest_off() {
    echo "longdong2 wlan-guest $@"

    uci batch << EOI
delete network.guest
delete wireless.guest1
delete wireless.guest2
delete dhcp.guest
$(uci show firewall | awk 'BEGIN { FS=OFS="." }
/guest/ { if (map[$2] != 1) { print "delete firewall."$2; map[$2]=1 } }')
EOI

    uci commit

    #XXX client not get ip-address from dhcp pool
    /etc/init.d/firewall reload
    /etc/init.d/network reload
}

wlan_private() {
    echo "longdong2 wlan-private $@"

    ssid=$1 && shift
    password=$1 && shift

    uci batch << EOI
set wireless.ssid0.ssid="$ssid"
set wireless.ssid4.ssid="$ssid"
set wireless.ssid0.encryption='psk-mixed+tkip+ccmp'
set wireless.ssid0.key="$password"
set wireless.ssid4.encryption='psk-mixed+tkip+ccmp'
set wireless.ssid4.key="$password"
EOI
    uci commit wireless
    /etc/init.d/network reload
}
