import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, add_mal_sites, get_cnx, check_duplicate
import string
import re

#These features are based on the domain name

#this function counts the number of vowels in a domain name
#http://www.mcafee.com/us/resources/white-papers/wp-mining-dns-for-malicious-domain-regist.pdf 
def find_vowels(domainName):
    d = str(domainName)
    count = 0
    total = 1
    vowels = {'a','e','i','o','u','y'}
    notLetters = {'1','2','3','4','5','6','7','8','9','.','-'}
    for letter in d:
        #if the character is a letter, count it in the total
        if letter not in notLetters:
            total += 1
                #if the letter is a vowel, count it as a vowel
        if letter in vowels:
            count += 1
    #if the percent of vowels is greater than 50%, return a value of 'true'
    percentage = count/float(total)
    if percentage > .5:
        return '1'

    

#Note-- we should change this function's name, because it doesn't actually find a percent
def percentDomainNum(dnsPackets):
	cnx = get_cnx()
	data = get_data(cnx, "SELECT DISTINCT domain, dst, ip FROM " +  dnsPackets + " AS distinctDNSPackets \
			     WHERE NOT EXISTS (SELECT domain,src,ip FROM malSites where malSites.domain = distinctDNSPackets.domain)")
	for d in data:
                #If the packet is internal, skip it
		if "in-addr" in d[0]:
			pass
		else:
                         #if the number of characters that are not letters (.ascii_letters) or punction is > 4, add as a threat
			if len( str(d[0]).translate(None,string.ascii_letters).translate(None,string.punctuation)) > 4:
				add_mal_sites(cnx, d)
			#if a domain name is over 50% vowels compared to consonants, add as a threat
			elif find_vowels(d[0])== '1':
                                add_mal_sites(cnx, d)
	cnx.close()

