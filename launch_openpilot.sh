#!/usr/bin/bash

# Next reboot should trigger an install without a reset
sudo rm /data/continue.sh

# Get Python working
ln -sfn $(pwd) /data/pythonpath
export PYTHONPATH="$PWD"

# Make it possible to write to /persist/tsk
trap "sudo mount -o remount,ro /persist" EXIT
sudo mount -o remount,rw /persist
sudo mkdir -p /persist/tsk || true
sudo chown comma /persist/tsk

# Run TSK Manager
python3 tsk/kbd.py
bash # Debug

# Clean up
sudo rm -rf /data/openpilot
# And done
sudo reboot

#exec ./launch_chffrplus.sh
