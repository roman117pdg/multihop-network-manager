#!/bin/bash

sudo touch /media/<user>/boot/ssh
sudo touch /media/<user>/boot/wpa_supplicant.conf
echo "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=PL

network={
	ssid=\"SSID_NAME\"
	psk=\"PASSWORD\"
	key_mgmt=WPA-PSK
}" > /media/mikolaj/boot/wpa_supplicant.conf
echo 'denyinterfaces wlan0' | sudo tee --append /media/<user>/rootfs/etc/dhcpcd.conf

