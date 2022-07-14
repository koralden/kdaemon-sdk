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

. /etc/fika_manager/common.sh

msg=""
code=404

account_cb() {
    act="unknown"
    [ $# -ge 1 ] && act=$1 && shift

    if [ "X$act" = "Xmodify" ]; then
        if [ $# -eq 2 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ modify"

            overwrite=$1 && shift
            if [ "Xon" = "X$overwrite" -o "Xtrue" = "X$overwrite" ]; then
                msg=$(account_modify $@)
                code=200
            else
                logger -s -t fika-manager -p debug "[$0] nothing"
            fi
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
            msg=$(wan_pppoe $@)
            code=200
        else
            logger -s -t fika-manager -p error "[$0] $@ wan pppoe"
            msg="invalid username or password"
            code=402
        fi
    elif [ "X$act" = "Xdhcp" ]; then
        logger -s -t fika-manager -p debug "[$0] $@ wan dhcp"
        msg=$(wan_dhcp $@)
    elif [ "X$act" = "Xwwan" ]; then
        if [ $# -ge 2 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ wan wwan"
            msg=$(wan_wwan $@)
        else
            logger -s -t fika-manager -p error "[$0] $@ wan wwan"
            msg="invalid username or password"
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
            msg=$(wlan_private $@)
            code=200
        else
            logger -s -t fika-manager -p error "[$0] $@ wlan private"
            msg="invalid SSID or PSK"
            code=402
        fi
    elif [ "X$act" = "Xguest" ]; then
        if [ $# -ge 1 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ wlan guest"
            msg=$(wlan_guest $@)
        else
            logger -s -t fika-manager -p error "[$0] $@ wlan guest"
            msg="invalid SSID"
            code=402
        fi
    else
        msg="wlan sub-cmd not support"
    fi
}

main() {
    cfg=$1 && shift

    type=$(echo $cfg | jq -r .wan_type)
    if [ "X$type" = "X1" ]; then
        username=$(echo $cfg | jq -r .wan_username)
        password=$(echo $cfg | jq -r .wan_passwod)
        wan_cb pppoe $username $password
    elif [ "X$type" = "X2" ]; then
        wan_cb wwan $username $password
    else
        wan_cb dhcp
    fi

    pssid=$(echo $cfg | jq -r .wifi_ssid)
    ppassword=$(echo $cfg | jq -r .wifi_password)
    wlan_cb private $pssid $ppassword

    [ $code -eq 200 ] && network_apply

    overwrite=$(echo $cfg | jq -r .password_overwrite)
    account_cb modify $overwrite $ppassword

    redis-cli publish kdaemon.easy.setup.ack success

    jq -rcM --null-input \
        --arg msg "$msg" \
        --argjson code "$code" \
        '{ "message": $msg, "code": $code }'
}

main $@
