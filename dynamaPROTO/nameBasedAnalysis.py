import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, add_mal_sites, get_cnx, check_duplicate
import string
import re
import logging, datetime
import os.path, time, datetime
workingDir = "/home/dynama/Desktop/prototype/dynamaPROTO" 
log = os.path.join(workingDir, 'dynamaLog.txt')

#This module focuses on the domain name to see if it is potentially malware.


#Percentage of numerical character in domain name.
def percentDomainNum():
	cnx = get_cnx()
	data = get_data(cnx, "SELECT DISTINCT sqlID, domain, dst, src FROM dnsPackets")

	for d in data:
		#checks to see how many numbers are in the domain name.
		if "in-addr" in d[1]:
			pass
		else:
			if len( str(d[1]).translate(None,string.ascii_letters).translate(None,string.punctuation)) >= 4 and len( str(d[1]).translate(None,string.ascii_letters).translate(None,string.punctuation)) < 6:
				threatLevel = 3
				tempList = [d[0],d[1],d[2],d[3],threatLevel]
				with open(log,"a") as mfh:
						mfh.write(str(datetime.datetime.now())+",nameV,"+str(threatLevel)+"\n")
				try:
					add_mal_sites(cnx, tempList)
				except:					
					pass
			elif len( str(d[1]).translate(None,string.ascii_letters).translate(None,string.punctuation)) >= 6 and len( str(d[1]).translate(None,string.ascii_letters).translate(None,string.punctuation)) < 8:
				threatLevel = 4
				tempList = [d[0],d[1],d[2],d[3],threatLevel]
				with open(log,"a") as mfh:
						mfh.write(str(datetime.datetime.now())+",nameV,"+str(threatLevel)+"\n")
				try:
					add_mal_sites(cnx, tempList)
				except:					
					pass
			elif len( str(d[1]).translate(None,string.ascii_letters).translate(None,string.punctuation)) >= 8:
				threatLevel = 5
				tempList = [d[0],d[1],d[2],d[3],threatLevel]
				with open(log,"a") as mfh:
						mfh.write(str(datetime.datetime.now())+",nameV,"+str(threatLevel)+"\n")
				try:
					add_mal_sites(cnx, tempList)
				except:					
					pass

	cnx.close()
#percentDomainNum()

def percentVowels():
	
	cnx = get_cnx()
	data = get_data(cnx, "SELECT DISTINCT sqlID, domain, dst, src FROM dnsPackets")
	vowels = "aeiouAEIOU"
	threatLevel = 0
	for d in data:
		if "in-addr" in d[1]:
			pass
		else:
			count = 0
			threatLevel = 0
			URLength = len(d[1])
			for letter in d[1]:
				if letter in vowels:
					count += 1
				ratio = count/float(URLength)
			if ratio < .15:
				threatLevel = 5
			elif ratio < .20:
				threatLevel = 4
			elif ratio < .25:
				threatLevel = 3
			if threatLevel > 0:
				tempList = [d[0],d[1],d[2],d[3],threatLevel]
				with open(log,"a") as mfh:
						mfh.write(str(datetime.datetime.now())+",nameV,"+str(threatLevel)+"\n")
				try:
					add_mal_sites(cnx, tempList)
				except:
					pass



