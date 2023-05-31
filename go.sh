#!/usr/bin/env bash

exe=target/release/lab-usage
destination='relliot_cat@ada.cs.pdx.edu:/u/relliot_cat/share/lab-usages/'
#rsync -r "${destination}/select/" "select"

mkdir -p output
for lab in $(cd select && ls); do
  echo "processing" $lab "..."
  ${exe} $(select/${lab}) > output/${lab}.csv
done

# files: rw-r----- = 640
#  dirs: rwxr-x--- = 750
chmod 750 output
chmod 640 output/*
rsync --recursive --perms output/ ${destination}
