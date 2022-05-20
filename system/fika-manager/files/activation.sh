#!/bin/sh

. /etc/fika_manager/common.sh
load_kdaemon_toml

get_boss_ap_token() {
    local token

    if token=$(fika-manager boss -w ${kdaemon_wallet_address} get-ap-token | jq -r .ap_token); then
        if [ -n "$token" ]; then
            fika_log info "kap.boss.ap.token as $token"
            update_kdaemon_toml ap_access_token "$token"
            return 0
        fi
    fi
    fika_log error "[kap][boss] GET ap-access-token fail"
}


main() {
    activation=$1 && shift

    newBossToken=$(echo "$activation" | jq -r .boss.access_token)
    newAwsToken=$(echo "$activation" | jq -r .aws.auth_token)

    cfgUpdate=false
    if [ "x$kdaemon_access_token" != "x$newBossToken" ]; then
        update_kdaemon_toml access_token "${newBossToken}"
        get_boss_ap_token
        cfgUpdate=true
    fi
    if [ "x$kdaemon_auth_token" != "x$newAwsToken" ]; then
        update_kdaemon_toml auth_token ${newAwsToken}
        cfgUpdate=true
    fi

    if $cfgUpdate; then
        sync;sync
        fika_log war "[$0] restart fika-manager & fika-easy-setup"
    fi
}

# obj as '{"boss":{"access_token":"...."},"aws":{"auth_token":"..."}}'
fika_log debug "[$0] $@"
main $@ && exit 0
