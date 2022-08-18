#!/bin/sh

fika_log() {
    level=$1 && shift

    if [ -e /dev/log ]; then
        logger -p ${level} "$@"
    else
        echo "[${level}] $@"
    fi
}
