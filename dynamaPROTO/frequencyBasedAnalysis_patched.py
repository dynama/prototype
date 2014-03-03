import mysql
import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, get_cnx, add_mal_sites, check_duplicate, add_sketch_sources, add_source_table
import sys, re, string
import config
network_address = config.networkAdd()
flush, fa, fb, fc = config.freqVars()
import os.path, time, datetime
workingDir = "/home/dynama/Desktop/prototype/dynamaPROTO" 
log = os.path.join(workingDir, 'dynamaLog.txt')

def analyzeTraffic1():
	cnx = get_cnx()
	cursor = cnx.cursor()
	data = get_data(cnx, "SELECT sqlID, domain, dst, src FROM dnsPackets where domain = 'Failed Lookup'")
	sketchyData = get_data(cnx, "SELECT DISTINCT dst FROM sketchySources")
	if sketchyData == []:
		newList = []
		print empty
		for d in data[0]:
			newList.append(d)
		firstLevel = 1
		newList.append(firstLevel)
		try:
			add_sketch_sources(cnx, newList)
		except:
			pass
	for item in data:
		print item
		for record in sketchyData:
			flag = 0
			if item[0] == record[2] :
				print "They Matched"
				flag = 1
				newList = []
				for d in record:
					newList.append(d)
				firstLevel = 1
				newList.append(firstLevel)
				try:
					add_sketch_sources(cnx, newList)
				except:
					pass		
			if flag != 0:
				findCurrentLevel = get_data(cnx, "SELECT DISTINCT level FROM sketchySources where dst = '"+item[2]+"'")
				print findCurrentLevel[0][0]
				newLevel = int(findCurrentLevel[0][0]) + 1
				newLevel = str(newLevel)
				updateStatement = ("UPDATE sketchySources SET level = "+newLevel+" WHERE dst = '"+item[2]+"'")
				cursor.execute(updateStatement)
		
#	add_sketch_sources(cnx, newList)


def analyzeTraffic():
    global network_address
    cnx = mysql.connector.connect(user='root', passwd='password', host = '127.0.0.1', database = 'dynama')
    cursor = cnx.cursor()
    pushBadSourcesQuery = ("SELECT sqlID, datetime, src, dst, dnsID, domain From dnsPackets WHERE dst!= '"+network_address+"'")
    cursor.execute(pushBadSourcesQuery)
    sourcesQueryResult = cursor.fetchall()
    for packet in sourcesQueryResult:
#	print packet
	try:
		add_source_table(cnx, packet)
	except:
		pass
    theQuery = ("SELECT DISTINCT domain, src FROM sourceTable")
    cursor.execute(theQuery)
    result = cursor.fetchall()
    for item in result:
		theQuery3 = ("SELECT COUNT(*) FROM sourceTable WHERE domain = '"+item[0]+"' and src = '"+item[1]+"'")
		cursor.execute(theQuery3)
		result3 = cursor.fetchone()
		secondSum = result3[0]
# 	   	theQuery2 = ("SELECT COUNT(*) FROM dnsPackets")
#  	  	cursor.execute(theQuery2)
#  	  	result2 = cursor.fetchone()
#   	 	firstSum = result2[0]
#		number = (secondSum/float(firstSum))
		if secondSum >= fa and secondSum < fb:
  		      	fprob = 2
		elif secondSum >= fb and secondSum < fc:
			fprob = 3
		elif secondSum >= fc:
			fprob = 4
		else:
 		       	fprob = 0
		if fprob > 0:
			with open(log,"a") as mfh:
						mfh.write(str(datetime.datetime.now())+",freqcy,"+str(fprob)+"\n")
			malQuery = ("SELECT sqlID, domain, dst, src from dnsPackets where domain = '"+item[0]+"' Limit 1")
			cursor.execute(malQuery)
			result4 = cursor.fetchone()
			newList = []
			try:
				for d in result4:
					newList.append(d)
				newList.append(fprob)
				try:
					add_sketch_sources(cnx, newList)
				except:
					pass
			except:
				pass
#analyzeTraffic1()
