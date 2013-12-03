#Builds and sends DNS packet to test Dynama
from scapy.all import *

packet = IP(dst='8.8.8.8')/UDP()/DNS()

packet.payload.payload.rd=1

packet.payload.payload.qd=DNSQR(qname="www.TooManyVowels.aeiouaeiouaeiouaeiou.com")
send(packet)
count = 0

while count < 50:

	send(packet)
	count +=1
	print packet.payload.payload.show2()
