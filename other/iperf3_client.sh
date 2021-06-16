#!/bin/bash

# set txpower to 0 dBm (help in testing)
sudo ifconfig wlan0 up
sudo iwconfig wlan0 txpower 0

# start given program in other process (not in console) and write output stream to logger file
# sudo python3 "./main.py" &
# sudo olsrd -i "wlan0" -d "1" &> "./logger.log" &
sudo batmand "wlan0" -d "1" &> "./logger.log" &

# wait until network is set
sleep 45

# set timestamp for end of experiment (60 seconds from this point)
end=$((SECONDS+60))

# start iperf3 client processes until end of experiment
while [ $SECONDS -lt $end ]; do
    # iperf3 --client "fe80::ba27:ebff:feb9:2696%wlan0" --port "5004"
    iperf3 -c "169.254.198.237" -p "5004"
done

# kill all started processes
sudo pkill --full iperf3*
#sudo pkill --full -SIGINT  *main.py*
#sudo pkill --full olsrd*
sudo pkill --full batmand*
