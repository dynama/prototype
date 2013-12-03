#!/usr/bin/env python

import sys, os, time
from dump_to_sql import dumper
from dnsBasedAnalysis import num_DNS_IP
from nameBasedAnalysis import percentDomainNum
from mySQL import get_data, get_cnx, add_mal_hosts
#from frequency import collects, analyzePercentActivity, analyzePercentToDestination


# How often the analysis tests are run
testInterval = 10

def checkInterface(): # Stolen with love from: https://github.com/kernel-sanders/Arsenic/blob/master/arsenic/nmapRunner.py
	file = os.popen("netstat -nr")
	data = file.read()
	file.close()
	lines = data.strip().split('\n')
	entriesList = []
	for line in lines:
		if line[:7] == '0.0.0.0':
			for entries in line.split(' '):
				if entries != '':
					entriesList.append(entries)
	return entriesList[7]
	
def main():
	
	#types of analysis
	analysis = ('percentDomainNum','num_DNS_IP')
	

	print 'Initializing Traffic Capture...',
	try:
	#iface = checkInterface()
		myDumper = dumper(checkInterface())
		myDumper.start()
		#time.sleep(5)
		print'COMPLETE'
	except:
		print 'ERROR'
		myDumper.stop()
	time.sleep(3)
	print 'Running analysis modules every ' + str(testInterval) + ' seconds...'

	testsRun = 0
	while(1):
		#print 'Initializing standard traffic patterns...',
		#srcSum, destSum, domKeys = collects()
		#print 'Running Activity Test...',
		#analyzePercentActivity(srcSum)
		#testsRun += 1
		#print 'Running Destination Test...',
		#analyzePercentToDestination(destSum,domKeys)
		#testsRun += 1
		print 'Running Numbers in Domain Test...',
		percentDomainNum()
		testsRun += 1
		#removeDup()
		print 'Checking for multiple return IPs...',
		num_DNS_IP()
		testsRun += 1
		print ' Done.'
		if testsRun == 0:
			print 'No analysis run'
		else:
			print str(testsRun) + ' analysis modules run'
			testsRun = 0
		time.sleep(testInterval)
		print 'Running meta analysis...',
		meta_analysis()
def meta_analysis():
	#use this to get info's from sql database
	#select src AS 'Potential Infected Hosts', high_number_count_in_name AS 'Queried Suspicious Domain Name(s)', high_amount_of_ips_per_domain AS 'Queried Domain that returned a high amount of IPs', total_number_of_flags AS 'Total Flags Triggered' from malHosts;
	cnx = get_cnx()
	print "Got Connection"
	data = get_data(cnx, "SELECT * FROM dnsPackets")
	print "Got Data"
	numFlag = 'No'
	IPFlag = 'No'
	totalFlag = 0
	repeat = 0
	
	percentDom = get_data(cnx, "SELECT src FROM malSites")
	numDNS = get_data(cnx, "SELECT src FROM multipleReturnIPs WHERE numIPs > 2")
	
	for d in data:
		double = get_data(cnx, "SELECT DISTINCT src FROM malHosts")
		numFlag = 'No'
		IPFlag = 'No'
		repeat = 0
		totalFlag = 0
		reFlag1 = 0
		reFlag2 = 0
		for x in double:
			if x[0] == d[3]:
				repeat = 1
	
		if repeat == 0:
			for p in percentDom:
				if d[3] == p[0]:
					numFlag = 'Yes'
					if reFlag1 == 0:
						totalFlag = totalFlag + 1
						reFlag1 = 1
			for n in numDNS:
				if d[3] == n[0]:
					IPFlag = 'Yes'
					if reFlag2 == 0:
						totalFlag = totalFlag + 1
						reFlag2 = 1
				
			if totalFlag > 0:
				add_mal_hosts(cnx, (d[3],numFlag,IPFlag,totalFlag))

	print 'COMPLETE'
	cnx.close()

if __name__ == '__main__':
	main()
