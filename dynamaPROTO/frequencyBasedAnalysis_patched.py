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
    src = network_address
    strsrc = str(src)
    theQuery = ("SELECT DISTINCT src FROM dnsPackets WHERE dst != '"+network_address+"'")
    cursor.execute(theQuery)
    result = cursor.fetchall()
    try:
	sketchySourceIP = result[0]
 	for item in sketchySourceIP:
		print item
		theQuery3 = ("SELECT COUNT(*) FROM dnsPackets WHERE src = '"+item+"'")
		cursor.execute(theQuery3)
		result3 = cursor.fetchone()
		secondSum = result3[0]
 	   	theQuery2 = ("SELECT COUNT(*) FROM dnsPackets")
  	  	cursor.execute(theQuery2)
  	  	result2 = cursor.fetchone()
   	 	firstSum = result2[0]
		print secondSum
   	 	print firstSum
		number = (secondSum/float(firstSum))
		print number
		if number > fa:
  		      	fprob = 4
		elif number > fb:
			fprob = .3
		elif number > fc:
			fprob = .4
		else:
 		       	fprob = 0
 	      	sprob = fprob
		print sprob
		cnx = get_cnx()
		malQuery = get_data(cnx, "SELECT sqlID, domain, dst, src from dnsPackets where src = '"+item+"' Limit 1")
		for d in malQuery:
			newList = []
			for part in d:
				newList.append(part)
			newList.append(sprob)
			print newList
			add_sketch_sources(cnx, newList, sprob)
		#malQuery = get_data(cnx, "SELECT sqlID, domain, dst, src from dnsPackets where src = '"+item+"' Limit 1")
		
			
    except: 
	pass
analyzeTraffic()
