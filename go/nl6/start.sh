sudo ulimit -Sn 10000000 # soft limit
sudo ulimit -Hn 10000000 # hard limit


sudo prlimit --nofile=5000000:5000000 ./start_all_devices.sh
