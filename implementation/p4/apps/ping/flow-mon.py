import fcntl
import os
import struct
import subprocess
from time import sleep
from datetime import datetime
import thread
import netifaces
import socket
from scapy.all import *
#from db import db
from time import sleep
import pcap

conf.use_pcap=True
ethintf_name=netifaces.interfaces()[1]
hostname=ethintf_name.split('-')[0]
flows_dict={}

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
s.bind((ethintf_name, ETH_P_ALL))
tun = open('/dev/net/tun', 'r+b')

def init():
    host_ip_mac={'h1':{'ip':'10.1.1.1','mac':'00:00:00:00:01:01'},
              'h2':{'ip':'10.1.1.2','mac':'00:00:00:00:01:02'},
              'h3':{'ip':'10.1.1.3','mac':'00:00:00:00:01:03'},
              'h4':{'ip':'10.1.1.4','mac':'00:00:00:00:01:04'},
              'h5':{'ip':'10.1.1.5','mac':'00:00:00:00:01:05'},
              'h6':{'ip':'10.1.1.6','mac':'00:00:00:00:01:06'}
              }
    tapintf_name=str('tap'+hostname)
    ethintf_mac=host_ip_mac[hostname]['mac']
    ethintf_ip=host_ip_mac[hostname]['ip']

    # Some constants used to ioctl the device file. I got them by a simple C
    # program.
    TUNSETIFF = 0x400454ca
    TUNSETOWNER = TUNSETIFF + 2
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    ETH_P_ALL=3
    # Open TUN device file.
    # Tall it we want a TUN device named tun0.
    print(tapintf_name)
    ifr = struct.pack('16sH', tapintf_name, IFF_TAP | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    # Optionally, we want it be accessed by the normal user.
    fcntl.ioctl(tun, TUNSETOWNER, 1000)

    # Bring it up and assign addresses.
    os.system('ifconfig '+ethintf_name+' 0')
    os.system('ifconfig '+tapintf_name+' '+ethintf_ip+' up')
    os.system('ifconfig '+tapintf_name+' hw ether '+ethintf_mac)
    for host in host_ip_mac:
        os.system('arp -s '+host_ip_mac[host]['ip']+' -i '+tapintf_name+' '+host_ip_mac[host]['mac'])
            
def worker1():
    while True:
        packet = list(os.read(tun.fileno(), 2048))
        #print 'sending packet of len %d'%(len(packet))
        #print datetime.now()
        s.send(''.join(packet))

def verify_flow_expire(db_inst):
    #set expiry time to 10msec
    expiry_time=10 
    db_inst.del_collection()
    while True:
        for key in flows_dict.keys():
            stats=flows_dict[key]
            timediff = (datetime.now()-stats['end']).total_seconds()*1000
            if timediff >= expiry_time:
                stats['log']=datetime.now()
                print('inserting',key,stats)
                db_inst.insert(stats)
                flows_dict.pop(key)
        sleep(1)
        
def worker2():
    while True:
        packet = s.recv(65565)
        eth_type=struct.unpack("!H",packet[12:14])[0]
        epoch_list=[]
        swid_list=[]
        stats={'sport':0,'dport':0,'sip':0,'dip':0,'proto':0,'tos':0,'bytes':0}
        flow_id=''
        first_vlan=True
        print('received packet')
        while eth_type==0x8100:
            if first_vlan:
                packet = packet[:12]+packet[(12+4):]
                eth_type=struct.unpack("!H",packet[12:14])[0]
                first_vlan=False
            sw_id = struct.unpack('!H',packet[14:16])[0]
            epoch = struct.unpack('!H',packet[18:20])[0]
            print('sw_id',sw_id,'epoch_id',epoch)
            swid_list.append(str(sw_id))
            epoch_list.append(epoch)
            packet = packet[:12]+packet[(12+8):]
            eth_type=struct.unpack("!H",packet[12:14])[0]
        if eth_type==0x0800:
            #print('IP eth_type',eth_type)
            iph=IP(packet[14:])
            #print iph.summary()
            stats['bytes']=iph.len
            stats['tos']=iph.tos
            stats['sip']=iph.src
            stats['dip']=iph.dst
            stats['proto']=iph.proto
            if stats['proto']==6:
                tcph=TCP(packet[34:])
                stats['sport']=tcph.sport
                stats['dport']=tcph.dport
            elif stats['proto']==17:
                udph=UDP(packet[34:])
                stats['sport']=udph.sport
                stats['dport']=udph.dport

        key=str(stats['sip'])+'-'+str(stats['sport'])+'-'+str(stats['dip'])+'-'+str(stats['dport'])+'-'+str(stats['proto'])+'-'+'-'.join(swid_list)

        if key not in flows_dict:
            start_time=datetime.now()
            flows_dict[key]={ 'id':key,
                              'sip':str(stats['sip']),
                              'dip':str(stats['dip']),
                              'sport':str(stats['sport']),
                                  'dport':str(stats['dport']),
                                  'proto':str(stats['proto']),
                                  'tos':str(stats['tos']),
                                  'pkts':1,
                                  'bytes':stats['bytes'],
                                  'epoch_list':epoch_list,
                                  'path':swid_list,
                                  'start':start_time,
                                  'end':start_time,
                                  'log':start_time
                                }
        else:
            flows_dict[key]['bytes'] +=stats['bytes']
            flows_dict[key]['pkts'] +=1
            flows_dict[key]['end']=datetime.now()
        os.write(tun.fileno(), ''.join(packet))


if __name__=="__main__":
    init()
    #db_inst=db(hostname)
    thread.start_new_thread(worker1,())
    thread.start_new_thread(worker2,())
    #sniff(iface=ethintf_name,prn=update_flow)
    #thread.start_new_thread(verify_flow_expire,(db_inst,))
    while 1:
        pass
    
