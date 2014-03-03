#Builds and sends DNS packet to test Dynama
from scapy.all import *
import os.path


def testshot():
        packet = IP(dst='8.8.8.8')/UDP()/DNS()
        packet.payload.payload.rd=1
        packet.payload.payload.qd=DNSQR(qname="www.aeiouaeiouaeiou.com")
        count = 0
        while count < 50:
                send(packet)
                count +=1
                print packet.payload.payload.show2()

##Loops through our pcap files and sends dns packets on the wire
def packetlooper():
        maldir = os.listdir('/home/dynama/Desktop/Crime')
        for filename in maldir:
                counter = 0
                #choose filename instead to loop through the directory
                pfile = os.path.join('/home/dynama/Desktop/Crime', 'cryptolocker_9CBB128E8211A7CD00729C159815CB1C.pcap')
                pcap = rdpcap(pfile)
                print "Now reading "+ filename
                confstring=raw_input("Continue? y/n ")
                if confstring == 'y':
                        #Loops through the packets in a file
                        for packet in pcap:
                                #searches for DNS packets and sends them
                                if 'Proto=DNS' or 'proto=dns' in packet:
                                        print type(packet)
                                        try:
                                                sendp(packet)
                                                counter += 1
                                        except:
                                                pass
                                else:
                                        print "not a dns packet!"
                        if counter > 0:
                                print "sent ",counter," dns packet(s)"
                                if filename == maldir[-1]:
                                        print "Packets Completed"
                                        break
                        else:
                                print "no dns packets detected"
                else:
                        print 'done!'
                        break
#testshot()                
packetlooper()
