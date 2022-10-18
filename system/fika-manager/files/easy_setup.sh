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

load_kdaemon_toml

msg=""
code=404
networkChg=false
DbKey="kap.system.config"

system_cb() {
    timezone_fix
}

account_cb() {
    act="unknown"
    [ $# -ge 1 ] && act=$1 && shift

    if [ "X$act" = "Xmodify" ]; then
        if [ $# -eq 2 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ modify"

            overwrite=$1 && shift
            if [ "Xon" = "X$overwrite" -o "Xtrue" = "X$overwrite" ]; then
                msg=$(account_modify "$1" $@)
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
            msg=$(wan_pppoe "$1" "$2" $@)
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
            msg=$(wan_wwan "$1" "$2" $@)
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
            msg=$(wlan_private "$1" "$2" $@)
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

cmp_wan() {
    local new_type orig_type new_username orig_username
    local new_password orig_password

    new=$1 && shift

    new_type=$(echo $new | jq -r .wan_type)
    orig_type=${kdaemon_wan_type}
    [ "X${new_type}" != "X${orig_type}" ] && return 0

    if [ "X$type" = "X1" ]; then
        new_username=$(echo $new | jq -r .wan_username)
        orig_username=${kdaemon_wan_username}
        [ "X${new_username}" != "X${orig_username}" ] && return 0

        new_password=$(echo $new | jq -r .wan_password)
        orig_password=${kdaemon_wan_password}
        [ "X${new_password}" != "X${orig_password}" ] && return 0
    fi

    return 127
}

cmp_wlan() {
    local new_ssid orig_ssid
    local new_password orig_password

    new=$1 && shift

    new_ssid=$(echo $new | jq -r .wifi_ssid)
    orig_ssid=${kdaemon_wifi_ssid}
    [ "X${new_ssid}" != "X${orig_ssid}" ] && return 0

    new_password=$(echo $new | jq -r .wifi_password)
    orig_password=${kdaemon_wifi_password}
    [ "X${new_password}" != "X${orig_password}" ] && return 0

    return 127
}

cmp_system_pwd() {
    local new_overwrt orig_overwrt
    local new_password orig_password

    new=$1 && shift

    new_overwrt=$(echo $new | jq -r .password_overwrite)
    orig_overwrt=${kdaemon_password_overwrite}
    [ "X${new_overwrt}" != "X${orig_overwrt}" ] && return 0

    new_password=$(echo $new | jq -r .wifi_password)
    orig_password=${kdaemon_wifi_password}
    [ "X${new_password}" != "X${orig_password}" ] && return 0

    return 127
}

main() {
    local type pssid ppassword overwrite
    cfg=$1 && shift

    system_cb

    if cmp_wan "$cfg"; then
        type=$(echo $cfg | jq -r .wan_type)
        if [ "X$type" = "X1" ]; then
            username=$(echo $cfg | jq -r .wan_username)
            password=$(echo $cfg | jq -r .wan_passwod)
            wan_cb pppoe "$username" "$password"

            update_kdaemon_toml wan_username "$username"
            update_kdaemon_toml wan_password "$password"
        elif [ "X$type" = "X2" ]; then
            wan_cb wwan "$username" "$password"
        else
            wan_cb dhcp
        fi
        networkChg=true
        update_kdaemon_toml_no_dq wan_type $type
    fi

    if cmp_wlan "$cfg"; then
        pssid=$(echo $cfg | jq -r .wifi_ssid)
        ppassword=$(echo $cfg | jq -r .wifi_password)

        wlan_cb private "$pssid" "$ppassword"
        networkChg=true
        update_kdaemon_toml wifi_ssid "$pssid"
        update_kdaemon_toml wifi_password "$ppassword"
    fi

    if cmp_system_pwd "$cfg"; then
        overwrite=$(echo $cfg | jq -r .password_overwrite)
        account_cb modify $overwrite "$ppassword"

        update_kdaemon_toml password_overwrite "$overwrite"
    fi

    if [ $code -eq 200 ]; then
        fika_redis PUBLISH ${DbKey}.ack success
    else
        fika_redis PUBLISH ${DbKey}.ack fail
    fi
    $networkChg && sleep 3 && network_apply

    jq -rcM --null-input \
        --arg msg "$msg" \
        --argjson code "$code" \
        '{ "message": $msg, "code": $code }'
}

[ $# -gt 0 ] && main "$@"
