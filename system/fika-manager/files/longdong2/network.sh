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
commit network
EOI
}

wan_dhcp() {
    echo "longdong2 wan-dhcp $@"
    uci batch <<EOI
set network.wan.proto=dhcp
commit network
EOI
}

wan_wwan() {
    echo "longdong2 wan-wwan $@"
}

wlan_guest_on() {
    echo "longdong2 wlan-guest $@"

    lanIpaddr=$(uci get network.lan.ipaddr)
    src=$(uci get firewall.@forwarding[-1].src)

    [ "Xkguest" = "X${src}" ] || uci batch << EOI
set network.kguest=interface
set network.kguest.type=bridge
set network.kguest.proto=static
set network.kguest.ipaddr=192.168.178.1
set network.kguest.netmask=255.255.255.0
set network.kguest.force_link=1
set network.kguest.multicast_querier=0
set network.kguest.igmp_snooping=0
set network.kguest.ieee1905managed=1

set wireless.kguest2=wifi-iface
set wireless.kguest2.device=wifi0
set wireless.kguest2.network=kguest
set wireless.kguest2.mode=ap
set wireless.kguest2.ssid=K-Public
set wireless.kguest2.encryption=none

set wireless.kguest5=wifi-iface
set wireless.kguest5.device=wifi1
set wireless.kguest5.network=kguest
set wireless.kguest5.mode=ap
set wireless.kguest5.ssid=K-Public
set wireless.kguest5.encryption=none

add_list dhcp.@dnsmasq[0].interface="kguest"
set dhcp.kguest=dhcp
set dhcp.kguest.interface=kguest
set dhcp.kguest.start=100
set dhcp.kguest.limit=150
set dhcp.kguest.leasetime=12h

set uhttpd.main.listen_http=$lanIpaddr:80
set uhttpd.main.listen_https=$lanIpaddr:443

add firewall zone
set firewall.@zone[-1].name=kguest
set firewall.@zone[-1].network=kguest
set firewall.@zone[-1].input=ACCEPT
set firewall.@zone[-1].output=ACCEPT
set firewall.@zone[-1].forward=ACCEPT
add firewall forwarding
set firewall.@forwarding[-1].src=kguest
set firewall.@forwarding[-1].dest=wan
commit
EOI

    echo "success"
}

wlan_guest_off() {
    echo "longdong2 wlan-guest $@"

    uci batch << EOI
delete network.kguest
delete wireless.kguest2
delete wireless.kguest5
del_list dhcp.@dnsmasq[0].interface="kguest"
delete dhcp.kguest
$(uci show firewall | awk 'BEGIN { FS=OFS="." }
/kguest/ { if (map[$2] != 1) { print "delete firewall."$2; map[$2]=1 } }')
commit
EOI
    echo "success"
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
commit wireless
EOI
}

network_apply() {
    echo 0 >/etc/firstLogin

    /etc/init.d/firewall reload
    /etc/init.d/network reload
    /etc/init.d/dnsmasq restart
    /etc/init.d/uhttpd restart
}
