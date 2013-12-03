__author__ =  'Ian Garrett/Erik Hunstad'
__version__=  '2.1'

import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, get_cnx, add_multipleReturnIP_data

"""This module conducts anaysis based on DNS traffic"""


"""Number of distinct IP addresses - the number of IP addresses resolved for
a given domain during defined time window"""
def num_DNS_IP(dnsPackets):
    cnx = get_cnx() # dst is a bug, should be src, can be fixed in mySQL.py (dst and src are swaped)
    dataSet = get_data(cnx, "SELECT DISTINCT datetime, dst, domain, NumOccurrences FROM \
                          (SELECT datetime, dst, domain, COUNT(datetime) \
                          AS NumOccurrences \
                          FROM " + dnsPackets + "  \
                          GROUP BY datetime  \
                          HAVING ( COUNT(datetime) > 1 )) AS UniqueMultipleReturnIPs\
                          WHERE NOT EXISTS (SELECT domain FROM multipleReturnIPs WHERE multipleReturnIPs.domain = UniqueMultipleReturnIPs.domain) \
                          GROUP BY domain") # http://stackoverflow.com/questions/3797799/show-all-rows-in-mysql-that-contain-the-same-value
    for data in dataSet:
        #print data
        add_multipleReturnIP_data(cnx, data)
    cnx.close()

"""Number of distinct countries"""
def num_countries():
    cnx = get_cnx()
    cnx.close()

"""Number of domains sharing the IP with"""
def num_sharing():
    cnx = get_cnx()
    cnx.close()

"""Reverse DNS query results - number of reverse DNS queries of the
returned IP addresses"""
def reverse_DNS_results():
    cnx = get_cnx()
    cnx.close()
