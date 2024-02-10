#!/usr/bin/env bash
set -o errexit

destination='/u/relliot_cat/share/lab-usage'

cargo build -r
cp 'target/release/lab-usage' -T ${destination}
chmod 750 ${destination}