#!/bin/sh

. /etc/fika_manager/common.sh

get_boss_ap_token() {
    local token
    load_kdaemon_toml

    if token=$(fika-manager boss -w ${kdaemon_wallet_address} get-ap-token | jaq -r .ap_token); then
        if [ -n "$token" ]; then
            fika_log info "kap.boss.ap.token as $token"
            update_kdaemon_toml boss.ap_access_token str "$token"
            return 0
        fi
    fi
    fika_log error "[kap][boss] GET ap-access-token fail"
}


main() {
    cfgUpdate=false
    activation=$1 && shift

    load_kdaemon_toml

    newWalletAddr=$(echo "$activation" | jaq -r .core.wallet_address)
    newUserWallet=$(echo "$activation" | jaq -r .core.user_wallet)
    newBossToken=$(echo "$activation" | jaq -r .boss.access_token)
    newBossApToken=$(echo "$activation" | jaq -r .boss.ap_access_token)
    newAwsToken=$(echo "$activation" | jaq -r .aws.auth_token)
    newPorNickname=$(echo "$activation" | jaq -r .por.nickname)

    if [ -n "$newWalletAddr" -a "$newWalletAddr" != "null" -a "x$kdaemon_wallet_address" != "x$newWalletAddr" ]; then
        update_kdaemon_toml core.wallet_address str "${newWalletAddr}"
        cfgUpdate=true
    fi
    if [ -n "$newUserWallet" -a "$newUserWallet" != "null" -a "x$kdaemon_user_wallet" != "x$newUserWallet" ]; then
        update_kdaemon_toml core.user_wallet str "${newUserWallet}"
        cfgUpdate=true
    fi
    if [ -n "$newBossToken" -a "$newBossToken" != "null" -a "x$kdaemon_access_token" != "x$newBossToken" ]; then
        update_kdaemon_toml boss.access_token str "${newBossToken}"
        cfgUpdate=true
    fi
    if [ "x$kdaemon_ap_access_token" = "x" ]; then
        if [ -z "$newBossApToken" -o "null" = "$newBossApToken" ]; then
            get_boss_ap_token
        else
            update_kdaemon_toml boss.ap_access_token str "${newBossApToken}"
        fi
        cfgUpdate=true
    fi
    if [ -n "$newAwsToken" -a "$newAwsToken" != "null" -a "x$kdaemon_auth_token" != "x$newAwsToken" ]; then
        update_kdaemon_toml aws.auth_token str ${newAwsToken}
        cfgUpdate=true
    fi

    if $cfgUpdate; then
        sync;sync
        fika_log war "[$0] restart fika-manager & fika-easy-setup"
    fi
}

# obj as '{"boss":{"access_token":"...."},"aws":{"auth_token":"..."}}'
fika_log debug "[$0] $@"
json=$1 && shift
main "$json" $@ && exit 0
