



import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, add_mal_sites, get_cnx, check_duplicate
import string
import re

#This module focuses on the domain name to see if it is potentially malware.


#Percentage of numerical character in domain name.
def percentDomainNum(dnsPackets):
	print "running name based analysis"
	cnx = get_cnx()
	data = get_data(cnx, "SELECT DISTINCT sqlID, domain, dst, ip FROM dnsPackets")

	for d in data:
		#checks to see how many numbers are in the domain name.
		if "in-addr" in d[1]:
			pass
		else:
			if len( str(d[1]).translate(None,string.ascii_letters).translate(None,string.punctuation)) >= 4 and len( str(d[1]).translate(None,string.ascii_letters).translate(None,string.punctuation)) < 6:
				threatLevel = 3
				tempList = [d[0],d[1],d[2],d[3],threatLevel]
				try:
					add_mal_sites(cnx, tempList)
				except:
					pass
			elif len( str(d[1]).translate(None,string.ascii_letters).translate(None,string.punctuation)) >= 6 and len( str(d[1]).translate(None,string.ascii_letters).translate(None,string.punctuation)) < 8:
				threatLevel = 4
				tempList = [d[0],d[1],d[2],d[3],threatLevel]
				try:
					add_mal_sites(cnx, tempList)
				except:
					pass
			elif len( str(d[1]).translate(None,string.ascii_letters).translate(None,string.punctuation)) >= 8:
				threatLevel = 5
				tempList = [d[0],d[1],d[2],d[3],threatLevel]
				try:
					add_mal_sites(cnx, tempList)
				except:
					pass

	cnx.close()
percentDomainNum("dnsPackets")
