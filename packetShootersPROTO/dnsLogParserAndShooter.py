# -*- coding: utf-8 -*-

import os, time,re
from scapy.all import *

logFile = r"/Desktop/dynama/patchedCode/packetShooters/2013-03-17.shortened.txt"
f = open(logFile, "r")
dnsLog=f.read()
f.close()

# finds the indexies for our packets by finding each <SEP>
packetIndexies = []
for m in re.finditer("<SEP>",dnsLog):
    packetIndexies.append([m.start(),m.end()])


# splits our packets on these idexies
splitPackets = []
oldDivider = [0,0]
count = 0

for index in packetIndexies:
    s = oldDivider[1]
    e = index[0]
    splitPackets.append(dnsLog[s+1:e].split(","))
    oldDivider = index

# separates out packets that don't fit the typical structure of len7    
lengthDict={7:0,8:0,9:0}
len7packetList = []

for i in splitPackets:
    y = len(i)
    if y == 7:
        lengthDict[7]+=1
        len7packetList.append(i)
    if y == 8:
        lengthDict[8]+=1
    if y == 9:
        lengthDict[9]+=1

#WHAT OUR PACKETS LOOK LIKE

##len7packetList[0] => date/time
##len7packetList[1] => source IP
##len7packetList[2] => destination IP
##len7packetList[3] => X
##len7packetList[4] => u
##len7packetList[5] => (q)query/(r)response
##len7packetList[6] => DNS query data


#finds queries only
dnsQueries = []
endings = []


for i in len7packetList:
    if i[5] == "q":
        h = i[6].rstrip()
        y = h.replace("NA\n? ","").split(" ")
        e = len(y)
        qTy = y[e-1].strip().upper()
        
        if qTy !=('TEXT') and qTy !=('PTR') and qTy !=('REDACTED'):
##            print qTy
##            print y
            dnsQueries.append(y)

            record = y[1]
            if record not in endings:
                endings.append(record)

##print endings                
##print dnsQueries

for i in dnsQueries:
    print i[0]
    print i[1]    
    packet = IP(dst='8.8.8.8')/UDP()/DNS(rd =1,qd=DNSQR(qname=i[0],qtype=i[1]))
    IP(dst='8.8.8.8')/UDP()/DNS(rd=1,qd=DNSQR(qname="www.TooManyNumbers987654321987654321.com"))
    # structure & qtype => theitgeekchronicles.files.wordpress.com/2012/05/scapyguide1.pdf‎
    
    send(packet)





























    
