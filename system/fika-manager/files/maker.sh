#!/bin/sh

odm_band="TODO"
serial_number="TODO"
model="TODO"
manufacture_date="TODO"
hw_version="TODO"
fw_version="TODO"
linux_version=$(uname -r)
sku="NCC"

jq -rcM --null-input \
    --arg band "$odm_band" \
    --arg sn "$serial_number" \
    --arg model "$model" \
    --arg mdate "$manufacture_date" \
    --arg hw "$hw_version" \
    --arg fw "$fw_version" \
    --arg linux "$linux_version" \
    --arg sku "$sku" \
    '{ "odm-band": $band, "serial-number": $sn, "model": $model, "manufacture-date": $mdate, "hw-version": $hw, "fw-version": $fw, "linux-version": $linux, "SKU": $sku }'
