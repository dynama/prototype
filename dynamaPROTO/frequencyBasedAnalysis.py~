import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, get_cnx#, add_sketchy_sources, add_sketchy_destinations
import sys, re
#These features are based on frequency of DNS traffic



def cross_reference_src_frequency(dnsPacketsVar):
    def frequency_src_IP(dnsPacketsVar):
        cnx = get_cnx()
        cursor = cnx.cursor()
        #flush out table for new data
        flush = ("DELETE FROM srcAnalysis WHERE sqlID > 0")
        cursor.execute(flush)
        sources = dict()
        sizeOfSources = len(sources)   
        #This portion collects the number of source addresses used
        cursor.execute("SELECT dst, ip, domain FROM "+ dnsPacketsVar)
        results = cursor.fetchall()
        for i in results:
            assert type(i[0]) is unicode        
            #add source to dictionary or add 1 to the frequency of that source
            if i[0] in sources.keys():
                sources[i[0]] = sources[i[0]] + 1.0
            else:
                try:
                    sources[i[0]].append(sources)
                except:
                    sources[i[0]] = 1.0
        numDNSRequestsToSource = sum(sources.values())
        #This portion analyzes the data received above
        percentPerSource = sources
        sourceKeys = sources.keys()
        sourceValues = sources.values() 
        #Identify the percent of DNS requests per source
        for i in sourceKeys:
            percentPerSource[i] = (percentPerSource[i]/numDNSRequestsToSource)*100
            data = (i, percentPerSource[i])
            addDNS = ("INSERT INTO srcAnalysis "
                       "(src, srcPercent) "#, domain) "
                       "VALUES (%s, %s)")#, %s)")
            cursor.execute(addDNS, data)
            cnx.commit()
        #print "COMPLETE frequency_src_IP"
        cnx.close()
    frequency_src_IP(dnsPacketsVar)
    cnx = get_cnx()
    cursor = cnx.cursor()
    flush = ("DELETE FROM sketchySources WHERE sqlID > 0")
    cursor.execute(flush)
    cursor.execute("SELECT src, srcPercent FROM srcAnalysis")
    srcResults = cursor.fetchall()
    for i in srcResults:
        if i[1] > 4.9: # threshold for sketchy host percentage of total traffic
            cursor.execute
            data = (i[0],)
            add_sketch_source = ("INSERT INTO sketchySources"
                            "(src)"
                            "VALUES (%s)")
            cursor.execute(add_sketch_source, data)
            cnx.commit()
    cnx.close()


def sources_by_destination(dnsPacketsVar):
    #because_local_global = list()
    def frequency_dst_IP(dnsPacketsVar):
        cnx = get_cnx()
        cursor = cnx.cursor()   
        flush = ("DELETE FROM dstAnalysis WHERE sqlID > 0")
        sourcesHax = dict()
        domains = dict()
        percentPerDestination = dict()
        cursor.execute(flush)
        cursor.execute("SELECT dst, domain, ip FROM " + dnsPacketsVar)
        results = cursor.fetchall()
        because_local_global = results
        for i in results:
            assert type(i[0]) is unicode
            #add domain to domains dictionary or add 1 to the frequency of that domain
            if i[1] in domains.keys():
                domains[i[1]] = domains[i[1]] + 1.0
            else:
                try:
                    domains[i[1]].append(domains)
                except:
                    domains[i[1]] = 1.0
            #adds the destination to the destination or add 1 to the frequency of that destination
            if i[2] in sourcesHax.keys():
                sourcesHax[i[2]] = sourcesHax[i[2]] + 1.0
            else:
                try:
                    sourcesHax[i[2]].append(sourcesHax)
                except:
                    sourcesHax[i[2]] = 1.0
        sizeOfDomains = sum(domains.values())
        domainKeys = domains.keys()
        #because_local_global = sourcesHax.keys()
        #Identify the percent of DNS requests per destination
        for i in domainKeys:
            percentPerDestination[i] = (domains[i]/sizeOfDomains)*100
            data = (i, percentPerDestination[i])
            addDNS = ("INSERT INTO dstAnalysis "
                       "(domain, dstPercent) "
                       "VALUES (%s, %s)")
            cursor.execute(addDNS, data)
            cnx.commit()
        #print "COMPLETE frequency_dst_IP"
        cnx.close()

    def cross_reference_destinations():
        cnx = get_cnx()
        cursor = cnx.cursor()
        flush = ("DELETE FROM sketchyDestinations WHERE sqlID > 0")
        cursor.execute(flush)
        cursor.execute("SELECT DISTINCT domain, dstPercent from dstAnalysis")
        dstResults = cursor.fetchall()
        for i in dstResults:
            if i[1] < 50.0: # threshold for sketchy domains
                data = i[0]
                #sketchyDestinationsHax + i[0]
                # mySQLString = 'INSERT INTO sketchyDestinations (sketchDst) VALUES ("' + data +'")'
                data = re.escape(data)
                mySQLString = 'INSERT INTO sketchyDestinations (sketchDst) VALUES ("' + data +'")'
                cnx.commit()
        cnx.close()


    frequency_dst_IP(dnsPacketsVar)    
    cross_reference_destinations()
    cnx = get_cnx()
    cursor = cnx.cursor()
    flush = ("DELETE FROM sketchySourcesByDomain WHERE sqlID > 0") # use truncate next version
    cursor.execute(flush)
    cursor.execute('SELECT dst, domain from ' + dnsPacketsVar + ' WHERE EXISTS (SELECT sketchDst FROM sketchyDestinations) Group by dst')
    #cursor.execute('SELECT dst, domain from dnsPackets WHERE EXISTS (SELECT sketchDst FROM sketchyDestinations)')
    finalResults = cursor.fetchall()
    for i in finalResults:
        data = i[0]
        data = re.escape(data)
        mySQLStrings = 'INSERT INTO sketchySourcesByDomain (src) VALUES ("' + data +'")'
        #print mySQLStrings
        cursor.execute(mySQLStrings)
        cnx.commit()
    cnx.close()
    ###Only select DISTINCT sketchySourcesByDomain

#check for duplicates
            #select domain from dns packets where source == schawatever
            #destination is the host on the local network and source is the query that they had
# frequency_src_IP()
# frequency_dst_IP()
# cross_reference_src_frequency()
# sources_by_destination(