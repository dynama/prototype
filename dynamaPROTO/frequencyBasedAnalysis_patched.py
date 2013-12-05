import mysql
import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, get_cnx, add_mal_sites, check_duplicate, add_sketch_sources
import sys, re, string
import config
network_address = config.networkAdd()
flush, fa, fb, fc = config.freqVars()



def analyzeTraffic():
    global network_address
    cnx = mysql.connector.connect(user='root', passwd='password', host = '127.0.0.1', database = 'dynama')
    cursor = cnx.cursor()
    pushBadSourcesQuery = ("SELECT * From dnsPackets WHERE dst!= '"+network_address+"'")
    cursor.execute(pushBadSourcesQuery)
    sourcesQueryResult = cursor.fetchall()
    for packet in sourcesQueryResult:
	add_source_table(cnx, packet)
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
		malQuery = ("SELECT sqlID, domain, dst, src from dnsPackets where domain = '"+item[0]+"' Limit 1")
		cursor.execute(malQuery)
		result4 = cursor.fetchone()
		newList = []
		for d in result4:
			newList.append(d)
		newList.append(fprob)
		print newList
		try:
			add_sketch_sources(cnx, newList)
		except:
			pass
analyzeTraffic()
