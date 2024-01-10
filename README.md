# Bluez-Sample

## Environment（Based on Raspberry Pi OS Lite）
$ sudo apt-get install libbluetooth-dev

$ sudo apt-get install bluez-hcidump

## Compile
$ gcc bluez_sample.c -lbluetooth -o bluez-sample

$ sudo ./bluez-sample
