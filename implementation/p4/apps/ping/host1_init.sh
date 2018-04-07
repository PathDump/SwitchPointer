ifconfig h1-eth0 hw ether 00:00:00:00:01:01
ifconfig h1-eth0 10.1.1.1
arp -i h1-eth0 -s 10.1.1.1 00:00:00:00:01:01
arp -i h1-eth0 -s 10.1.1.2 00:00:00:00:01:02
ifconfig h1-eth0 mtu 1400

