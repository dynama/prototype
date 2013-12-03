#import MySQL
import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, get_cnx, add_mal_sites, check_duplicate
import sys, re, string
import config
# sourceTable is where we put all network queries, source is the attribute
# sketchySource is where we put naughty queries when they misbehave.   
global network_address
network_address = config.networkAdd()
global flush, threshold
flush, threshold = config.freqVars()
global count
count = 0


def analyzeTraffic(table):
    global network_address
    cnx = get_cnx()
    data = get_data(cnx, "SELECT * FROM "+ table)
    for x in data:
        if network_address in x[3]:
            print x[2], x[3]
            addDNS = ("INSERT INTO sourceTable "
                           "(source)"
                           "VALUES ("+x[2]+")")
        
    #+" WHERE dst= "+ network_address+";")
##    cursor = cnx.cursor()
##    addDNS = ("INSERT INTO sourceTable "
##                   "(source)"
##                   "VALUES (%s)")
##    cursor.execute(addDNS, data)
##    cnx.commit()        
    cnx.close()

def analyzeQueries(table, field):
    cnx = get_cnx()
    data = get_data(cnx, "SELECT " + field + ", COUNT(*) FROM "+ table + " GROUP BY " + field)
    global count
    count+=1        
    cnx.close()    

def flushsources():
    cnx = mysql.connector.connect(user='root', passwd='password', host = '127.0.0.1', database = 'dynama')
    cursor = cnx.cursor()    
    executeflush = ("DELETE FROM sourceTable WHERE sqlID > 0")
    cursor.execute(executeflush)
    global count
    count = 0
    

def main():
    
    if count > flush:
        flushsources()
    
def test():
    analyzeTraffic("dnsPackets")
    analyzeTraffic("dnsPackets2")
    analyzeTraffic("multipleReturnIPs")
    #analyzeQueries("sourceTable", "source")

test()
