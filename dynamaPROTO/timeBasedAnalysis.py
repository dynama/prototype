__author__ =  'Ian Garrett'
__version__=  '2.1'

import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, get_cnx

"""These features are based on the network over time"""

"""Short lived domain
Based on the fact that a domain will have at least several
queries if it is legitimate"""
def short_Domain_analysis():
	cnx = get_cnx()	
	cnx.close()

"""Daily similarity
Checks to see what is regular traffic and what is drastically
different"""
def daily_similarity_analysis():
	cnx = get_cnx()
	cnx.close()

"""Repeating pattern
Based on if a domain is requested at certain time in a given
interval"""
def repeating_pattern_analysis():
	cnx = get_cnx()
	cnx.close()

"""Access Ratio
Checks to see if domain is gernally in an idle state or
accessed continuously"""
def access_ratio_analysis():
	cnx = get_cnx()
	cnx.close()
