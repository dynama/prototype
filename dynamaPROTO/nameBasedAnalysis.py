import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, add_mal_sites, get_cnx, check_duplicate
import string
import re
import logging, datetime
import os.path, time, datetime
workingDir = "/home/dynama/Desktop/prototype/dynamaPROTO" 
log = os.path.join(workingDir, 'dynamaLog.txt')

#This module focuses on the domain name to see if it is potentially malware. It looks at both the percentage of
#numbers compared to letters in the domain name, and also looks at the ratio of vowels to consonants.
#The purpose of this is to find domain names that do not appear to be legit domain names because they are more
#likely to contain malware.


#Percentage of numerical character in domain name. This module takes the length of the domain name and takes
#the number of numbers and letters and finds out the percentage of the domain name that is made up of numbers.
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

#This function looks at the ratio of vowels to consonants.
#It looks at the total number of letters and finds out how many are vowels divides it by the total number of letters
#to see the ratio of the vowels to consonants.
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



