__author__ =  'Erik Hunstad'
__version__=  '2.1'

import sqlite3, os, signal, threading, time, subprocess, sys
from datetime import datetime
from mySQL import initialize_database
from parser import parse_output

class dumper(threading.Thread):
	"""
	This class sets up a threaded tshark (terminal wireshark) and inserts any packets it captures into
	a mySQL database running on the same machine. This database has one table called dnsPackets which stores
	the GMT time the packet was captures, the source IP (host IP), the destination IP
	(DNS server or router), the domain the host is looking up and the ip (if any) that was returned.
	"""
	def __init__(self, iface, analysisInterval, printQueue):
		"""
		Arguments:
		iface - the interface to capture on
		analysisInterval - how often to run the analysis modules
		printQueue - the queue to put strings that will be printed to the screen with curses
		"""
		self.printQueue = printQueue
		self.iface = "eth0"
		self.analysisInterval = analysisInterval
		self.analysisTable = "dnsPackets"
		self.stopDump = threading.Event()
		super(dumper,self).__init__()

	def run(self):
		"""
		The main function of the capture thread, this function spawns tshark to do the packet
		capture and then switches the dnsPacket table in and out every time the analysis suite
		is run. This keeps the actual number of full packets on the system at any one time to 
		a minimum. The table used to store packets is truncated after it is analyzed.
		"""
		# Set up a new database if one doesn't already exist. Create the table for dnsPackets.
		self.cursor, self.cnx = initialize_database()
		# This is the actual tshark command to start the capture, it will only capture DNS responses.
		self.p1 = subprocess.Popen('tshark -i ' + self.iface + ' -R "dns" -o column.format:""No.","%m", "Time", "%Yt", "Source", "%s", "Destination", "%d", "ID", "%Cus:dns.id", "Info", "%i""', shell=True, stdout=subprocess.PIPE) # http://unix.stackexchange.com/questions/27246/how-to-gather-dns-a-record-requests
		
		currentTable = 'dnsPackets'
		while not self.stopDump.isSet():
			lastSwitch = time.time() 
			if time.time() - lastSwitch >= self.analysisInterval: # switch between two tables so analysis can run on a static table
				if currentTable == 'dnsPackets':
					currentTable = 'dnsPackets2'
					self.analysisTable = 'dnsPackets'
					self.printQueue.put("Switched dumper to dnsPackets2")
				else:
					currentTable = 'dnsPackets'
					self.analysisTable = 'dnsPackets2'
					self.printQueue.put("Switched dumper to dnsPackets")
				lastSwitch = time.time()

			out = self.p1.stdout.readline()
			if len(out) > 0:
				#print out
				parse_output(self.cnx, out, currentTable)

	def get_analysis_table(self):
		"""
		Return the SQL table that is currently being used for analysis (not having packets inserted into it)
		"""
		return self.analysisTable

	def get_cnx(self):
		return self.cnx

	def join(self, timeout=None):
		"""
		This function is called to safely halt the packet capture thread, and the tshark process it spawned.
		"""
		self.stopDump.set()
		self.cursor.close()
		self.cnx.close()
		self.p1.terminate()
		super(dumper, self).join(timeout)

# A simple tester to make sure it works properly. 
# def main():
# 	try:
# 		myDumper = dumper('eth1')
# 		myDumper.start()
# 	except KeyboardInterrupt:
# 		myDumper.stop()
# 	except:
# 		print 'error'
# 		myDumper.stop()

# if __name__ == '__main__':
# 	main()
