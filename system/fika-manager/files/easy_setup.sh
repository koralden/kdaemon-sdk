#!/bin/sh

# {account|wan|wlan|pairing} {sub-opt} {opt-arg} ...
# account
#       - modify {username} {password}
# wan
#       - pppoe {username} {password}
#       - dhcp
#       - wwan {username} {password} {pincode}  - option
# wlan
#       - private {SSID} {PSK}
#       - guest {SSID}
# pairing                                       - option
#       - otp {OTP}
#       - owner {wallet} {GPS}
#
# ref
#       - https://openwrt.org/docs/guide-user/network/wan/wan_interface_protocols
#       - https://openwrt.org/docs/guide-user/base-system/basic-networking

msg=""
code=404
cmd="unknown"
[ $# -ge 1 ] && cmd=$1 && shift


account_cb() {
    act="unknown"
    [ $# -ge 1 ] && act=$1 && shift

    if [ "X$act" = "Xmodify" ]; then
        if [ $# -eq 2 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ modify"
            msg="TODO"
            code=200
        else
            logger -s -t fika-manager -p error "[$0] $@ modify"
            msg="invalid username or password"
            code=402
        fi
    else
            logger -s -t fika-manager -p error "[$0] $@"
        msg="sub-command not support"
    fi
}

wan_cb() {
    act="unknown"
    [ $# -ge 1 ] && act=$1 && shift

    if [ "X$act" = "Xpppoe" ]; then
        if [ $# -ge 2 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ wan pppoe"
            msg="TODO"
        else
            logger -s -t fika-manager -p error "[$0] $@ wan pppoe"
            msg="invalid username or password"
            code=402
        fi
    elif [ "X$act" = "Xdhcp" ]; then
        logger -s -t fika-manager -p debug "[$0] $@ wan dhcp"
        msg="TODO"
    elif [ "X$act" = "Xwwan" ]; then
        if [ $# -ge 3 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ wan wwan"
            msg="TODO"
        else
            logger -s -t fika-manager -p error "[$0] $@ wan wwan"
            msg="invalid MAC address"
            code=402
        fi
    else
        msg="wan type not support"
    fi
}

wlan_cb() {
    act="unknown"
    [ $# -ge 1 ] && act=$1 && shift

    if [ "X$act" = "Xprivate" ]; then
        if [ $# -ge 2 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ wlan private"
            msg="TODO"
        else
            logger -s -t fika-manager -p error "[$0] $@ wlan private"
            msg="invalid SSID or PSK"
            code=402
        fi
    elif [ "X$act" = "Xguest" ]; then
        if [ $# -ge 1 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ wlan guest"
            msg="TODO"
        else
            logger -s -t fika-manager -p error "[$0] $@ wlan guest"
            msg="invalid SSID"
            code=402
        fi
    else
        msg="wlan sub-cmd not support"
    fi
}

pairing_cb() {
    act="unknown"
    [ $# -ge 1 ] && act=$1 && shift

    if [ "X$act" = "Xotp" ]; then
        if [ $# -ge 1 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ pairing otp"
            msg="TODO"
        else
            logger -s -t fika-manager -p error "[$0] $@ pairing otp"
            msg="invalid OTP"
            code=402
        fi
    elif [ "X$act" = "Xowner" ]; then
        if [ $# -ge 2 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ pairing owner"
            msg="TODO"
        else
            logger -s -t fika-manager -p error "[$0] $@ pairing owner"
            msg="invalid wallet or GPS"
            code=402
        fi
    else
        msg="pairing sub-cmd not support"
    fi
}
if [ "X$cmd" = "Xaccount" ]; then
    account_cb $@
elif [ "X$cmd" = "Xwan" ]; then
    wan_cb $@
elif [ "X$cmd" = "Xwlan" ]; then
    wlan_cb $@
elif [ "X$cmd" = "Xpairing" ]; then
    pairing_cb $@
else
    msg="command not support"
fi

jq -rcM --null-input \
    --arg msg "$msg" \
    --argjson code "$code" \
    '{ "message": $msg, "code": $code }'
