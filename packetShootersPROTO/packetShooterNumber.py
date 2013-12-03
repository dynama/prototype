#Builds and sends DNS packet to test Dynama
from scapy.all import *

##http://www.secdev.org/projects/scapy/doc/usage.html

packet = IP(dst='8.8.8.8')/UDP()/DNS(rd=1,qd=DNSQR(qname="www.TooManyNumbers987654321987654321.com"))

##packet.payload.payload.rd=1
##packet.payload.payload.qd=DNSQR(qname="www.TooManyNumbers987654321987654321.com")

count = 0

while count < 20:

	send(packet)
	count +=1
	print packet.payload.payload.show2()
