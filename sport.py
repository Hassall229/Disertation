#!/usr/bin/env python

import dpkt
import datetime
import socket
import matplotlib.pyplot as plt
import sys
import numpy as np



f = open('Networkcapture1.pcap')
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data

    if isinstance(ip.data, dpkt.tcp.TCP):
	tcp = ip.data
        print 'Src. Port: %s' % (tcp.sport)
	#socket.gethostbyname(socket.gethostname())
	#print 
# Displays date and time (based on computer, needs to be changed to file times)
	TimeStamp = datetime.datetime.now() 
	print str(TimeStamp)
	

f.close()
