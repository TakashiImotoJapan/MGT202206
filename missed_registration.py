#!/usr/bin/python

from scapy.all import *
import base64

flag = ""
packets = rdpcap("cap.pcap")

for frame in packets:
    if "&x" in str(frame.getlayer(IP)):
        data = str(frame)
        # extract hex
        flag += data[data.find("&x=")+3:-1]

with open("hex.txt",'w') as f:
    f.write(flag)
