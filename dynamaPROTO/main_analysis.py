import sys, os, time
from dump_to_sql import dumper
from mySQL import truncate_table, get_cnx, get_data, update_mal_hosts
from nameBasedAnalysis import percentDomainNum
from nameBasedAnalysis import percentVowels
from frequencyBasedAnalysis_patched import analyzeTraffic
from probability import getprob
import threading, Queue
import os.path, time, datetime
workingDir = "/home/dynama/Desktop/prototype/dynamaPROTO" 
log = os.path.join(workingDir, 'dynamaLog.txt')

#This module serves as the main module for dynama. It calls all of the different analyzing modules for the program. 

class main_analysis(threading.Thread):
	""" This thread will run all the analysis every
		analysisInterval seconds after starting the 
		traffic capture in a separate thread. It communicates 
		to the main curses thread with a queue.
	"""
	def __init__(self, analysisInterval, commiunicationQueue):
		self.commiunicationQueue = commiunicationQueue
		self.analysisInterval = float(analysisInterval) # How often the analysis modules are run
		self.stopAnalysis = threading.Event()
		super(main_analysis, self).__init__()

	def start_traffic_capture(self):
		self.commiunicationQueue.put('Initializing Traffic Capture...')
		try:
#	Supposed to auto read the interface on the machine to capture on, does not currently work, so it is hard coded in.
#			iface = checkInterface()
#			self.myDumper = dumper(iface, self.analysisInterval, self.commiunicationQueue)
			self.myDumper = dumper("eth0", self.analysisInterval, self.commiunicationQueue)
			self.myDumper.start()
			self.commiunicationQueue.put('COMPLETE')
		except:
			self.commiunicationQueue.put('ERROR')
			try:
				self.myDumper.stop()
			except:
				pass

	def run(self):
		self.commiunicationQueue.put('Running analysis modules every ' + str(self.analysisInterval) + ' seconds...')
		time.sleep(self.analysisInterval)
		analysisModulesRun = 0
		cnx = get_cnx()
		while not self.stopAnalysis.isSet():
			currentDNSTable = self.myDumper.get_analysis_table()
			self.commiunicationQueue.put('Frequency Based Analysis in progress...')
			analyzeTraffic()
			analysisModulesRun += 1
			self.commiunicationQueue.put('Done.')
			self.commiunicationQueue.put('Name Based Analysis in progress...')
			percentDomainNum()
			percentVowels()
			analysisModulesRun += 1
			self.commiunicationQueue.put('Done.')
			self.commiunicationQueue.put('Compiling Probability...')
			getprob()
			analysisModulesRun += 1
			self.commiunicationQueue.put('Done.')
			if analysisModulesRun == 0:
				self.commiunicationQueue.put('No analysis run')
			else:
				self.commiunicationQueue.put(str(analysisModulesRun) + ' analysis modules run')
				analysisModulesRun = 0
			truncate_table(cnx, currentDNSTable) 
			# delete all data once we have analyzed it ## Future work, get this to work when no data is coming in
			time.sleep(self.analysisInterval)

	def join(self, timeout=None):
		self.myDumper.join()
		self.stopAnalysis.set()
		super(main_analysis, self).join(timeout)

	def meta_analysis(self):
		cnx = get_cnx()
		analysisTables = [('malSites','high_number_count_in_name','"Yes","No","No","No"'), ('multipleReturnIPs','high_amount_of_ips_per_domain','"No","Yes","No","No"'), ('sketchySources', 'sketchy_src', '"No","No","Yes","No"'),('sketchySourcesByDomain', 'sketchy_browse', '"No","No","No","Yes"')]
		for tables in analysisTables:
			try:
				sources = get_data(cnx, "SELECT src FROM " + tables[0])
			except:
				self.commiunicationQueue.put("No data in " + tables[0])
				sources = []
			for src in sources:
				update_mal_hosts(cnx,src[0],tables[1],tables[2])  

	def check_interface(self): # https://github.com/kernel-sanders/Arsenic/blob/master/arsenic/nmapRunner.py
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


