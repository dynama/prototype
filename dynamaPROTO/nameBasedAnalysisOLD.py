import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, add_mal_sites, get_cnx, check_duplicate
import string
import re

#These features are based on the domain name


#Percentage of numerical character in domain name
def percentDomainNum(dnsTable):
	cnx = get_cnx()
	data = get_data(cnx, "SELECT DISTINCT domain, dst, ip FROM " +  dnsTable + " AS distinctDNSPackets \
			     WHERE NOT EXISTS (SELECT domain,src,ip FROM malSites where malSites.domain = distinctDNSPackets.domain)")
	for d in data:
		#checks to see how many numbers are in the domain name
		if "in-addr" in d[0]:
			pass
		else:	
			if len( str(d[0]).translate(None,string.ascii_letters).translate(None,string.punctuation)) >= 4 and len( str(d[0]).translate(None,string.ascii_letters).translate(None,string.punctuation)) < 6:
				threatLevel = 3
				tempList = [d[0],d[1],d[2],d[3],threatLevel]
				add_mal_sites(cnx, tempList)
			elif len( str(d[0]).translate(None,string.ascii_letters).translate(None,string.punctuation)) >= 6 and len( str(d[0]).translate(None,string.ascii_letters).translate(None,string.punctuation)) < 8:
				threatLevel = 4
				tempList = [d[0],d[1],d[2],d[3],threatLevel]
				add_mal_sites(cnx, tempList)
			elif len( str(d[0]).translate(None,string.ascii_letters).translate(None,string.punctuation)) >= 8:
				threatLevel = 5
				tempList = [d[0],d[1],d[2],d[3],threatLevel]
				add_mal_sites(cnx, tempList)
	cnx.close()

