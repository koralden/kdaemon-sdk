#!/bin/sh

# {account|firewall} {add|remove|update} {sub-opt} {opt-arg} ...
# account
#       - register {username} {password}
#       - login {username} {password}
#       - delete {username}
# firewall
#       - add {mac-addr} {ip-addr} {start-time} {end-time} {bandwidth}
#       - delete {mac-addr}
#       - update {mac-addr} {start-time} {end-time} {bandwidth}

. /etc/fika_manager/common.sh

msg=""
code=404
cmd="unknown"
[ $# -ge 1 ] && cmd=$1 && shift


account_cb() {
    act="unknown"
    [ $# -ge 1 ] && act=$1 && shift

    if [ "X$act" = "Xregister" ]; then
        msg="TODO"
        logger -s -t fika-manager -p debug "[$0] $@ register"
    elif [ "X$act" = "Xlogin" ]; then
        if [ $# -eq 2 ]; then
            msg="success"
            code=200
            logger -s -t fika-manager -p info "[$0] $1 login"
        else
            logger -s -t fika-manager -p error "[$0] $@ login"
            msg="invalid username or password"
            code=402
        fi
    elif [ "X$act" = "Xdelete" ]; then
        logger -s -t fika-manager -p debug "[$0] $@ delete"
        msg="TODO"
    else
            logger -s -t fika-manager -p error "[$0] $@"
        msg="command not support"
    fi
}

firewall_cb() {
    act="unknown"
    [ $# -ge 1 ] && act=$1 && shift

    if [ "X$act" = "Xadd" ]; then
        if [ $# -ge 2 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ firewall add"
            msg=$(firewall_add $@)
        else
            logger -s -t fika-manager -p error "[$0] $@ firewall add"
            msg="invalid MAC or IP address"
            code=402
        fi
    elif [ "X$act" = "Xdelete" ]; then
        if [ $# -eq 1 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ delete"
            msg=$(firewall_delete $@)
        else
            logger -s -t fika-manager -p error "[$0] $@ delete"
            msg="invalid MAC address"
            code=402
        fi
    elif [ "X$act" = "Xupdate" ]; then
        if [ $# -ge 3 ]; then
            logger -s -t fika-manager -p debug "[$0] $@ update"
            msg=$(firewall_update $@)
        else
            logger -s -t fika-manager -p error "[$0] $@ update"
            msg="invalid MAC address"
            code=402
        fi
    else
        msg="command not support"
    fi
}

if [ X"$cmd" = "Xaccount" ]; then
    account_cb $@
elif [ X"$cmd" = "Xfirewall" ]; then
    firewall_cb $@
else
    echo "WTF"
fi

jq -rcM --null-input \
    --arg msg "$msg" \
    --argjson code "$code" \
    '{ "message": $msg, "code": $code }'
