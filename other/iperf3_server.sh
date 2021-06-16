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

# create logger file
touch "logger.log"
echo "--------------------------------------------------------------" &>> "/home/pi/iperf3/logger.log"
echo "---------------------starting new program---------------------" &>> "/home/pi/iperf3/logger.log"
echo "--------------------------------------------------------------" &>> "/home/pi/iperf3/logger.log"
   
# start 4 iperf3 server processes on difrent ports and create logger files for them
for i in {1..4}
do
   touch "/home/pi/iperf3/logger$i.log"
   # iperf3 --server --port "500$i" &> "/home/pi/iperf3/logger$i.log" &
   iperf3 -s -p "500$i" &> "/home/pi/iperf3/logger$i.log" &
done

# wait 1 minute for end of experiment
sleep 60

# write logger files to one main file
for i in {1..4}
do
   echo "--------------------------------------------------------------" &>> "/home/pi/iperf3/logger.log"
   echo "---------------------iperf3 on port 500$i---------------------" &>> "/home/pi/iperf3/logger.log"
   echo "--------------------------------------------------------------" &>> "/home/pi/iperf3/logger.log"
   cat "/home/pi/iperf3/logger$i.log" &>> "/home/pi/iperf3/logger.log"
done

# kill all started processes
sudo pkill --full iperf3*
#sudo pkill --full -SIGINT  *main.py*
#sudo pkill --full olsrd*
sudo pkill --full batmand*
