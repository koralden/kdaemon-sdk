#!/bin/sh

. /etc/fika_manager/common.sh
. /etc/fika_manager/provision.sh library

# {cmd} {ap-info json string}

fika_log debug "[$0] $@"

info=$1 && shift

redis-cli SET kap.boss.ap.info ${info} 2>&1 >/dev/null
fika_log info "[$0] save ${info} into kap.boss.ap.info"

provision_sync_aws

