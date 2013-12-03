# sudo tshark -i eth1 -R "dns" -o column.format:""No.","%m", "Time", "%Yt", "Source", "%s", "Destination", "%d", "ID", "%Cus:dns.id", "Info", "%i""


import re
from Queue import PriorityQueue
import time
import dateutil.parser
from decimal import Decimal
from collections import OrderedDict

from mySQL import add_dns_data

orderedDict = OrderedDict()
dnsIDDict = dict()
bufferEntry = ('empty','empty')

def parse_output(cnx, out, dnsTable):
    global bufferEntry
    isRequest = False
    badRequest = False
    serverFailure = False
    portUnreachable = False
    gmttime = out[0:26]
    responseIPs = []
    #print 'time: ' + gmttime
    # This next line will melt your face. 
    # It takes the gmttime string, parses it into a tuple, which is only accurate to the second,
    # converts that into unix time, strips the ".0" off 
    # and appends the actual decimal from the gmttime, then turns that string into a Decimal object.
    # Boom. Try that in C! Now we have 1/100000 second accuracy and in unix time format.
    unixTime = Decimal(str(time.mktime(dateutil.parser.parse(gmttime).timetuple()))[:-2] + gmttime[-7:]) # http://stackoverflow.com/questions/2775864/python-datetime-to-unix-timestamp and http://stackoverflow.com/questions/1995615/python-how-can-i-format-a-decimal-to-always-show-2-decimal-places
    #print 'unix time: ' + str(unixTime)
    try:
        src = re.search( r'[0-9]+(?:\.[0-9]+){3}', out[26:41]).group()
    except:
        src = ''
    print 'src: ' + src
    try:
        dst = re.search( r'[0-9]+(?:\.[0-9]+){3}', out[43:57]).group()
    except:
        dst = ''
    print 'dst: ' + dst
    dnsID = out[56:62]
    print 'dnsID: ' + dnsID
    print out[88:100]
    if out[78:86] == "response":
        #print 'response'
        if out[88:100] != 'No such name':
            payload = out[78:]
            responseIPs = re.findall( r'[0-9]+(?:\.[0-9]+){3}', payload) # http://stackoverflow.com/questions/2890896/extract-ip-address-from-an-html-string-python
            #for ips in responseIPs:
            #    print 'ip: '+ ips
            if len(responseIPs) == 0:
                if 'Server failure' in payload:
                    serverFailure = True
        else:
            badRequest = True
    elif out[63:105] == 'Destination unreachable (Port unreachable)':
        portUnreachable = True
    else:
        isRequest = True
        lookupDomain = out[80:]
        lookupDomain = lookupDomain[:-1]
        #print 'domain: ' + lookupDomain

    if isRequest:
        dnsIDDict[dnsID] = (gmttime, src, dst, dnsID, lookupDomain) # store the domain in the dict for when the response comes
        orderedDict[dnsID] = unixTime # store the domain id in and ordered dictionary with the value of the unix time of the request
        #check_for_old(cnx, 2, dnsTable) ## Future work, get this to work (problem with buffered output from T-shark makes the timestamps old when we get them)
    else: 
        if dnsID in dnsIDDict:
            #print 'DATA:'
            foundDomain = dnsIDDict[dnsID][4] # only do one lookup
            if badRequest:
                data = (gmttime, src, dst, dnsID, foundDomain, 'Bad Request')
                #print data
            elif serverFailure:
                data = (gmttime, src, dst, dnsID, foundDomain, 'Server failure')
            elif portUnreachable:
                data = (gmttime, src, dst, dnsID, foundDomain, 'Port unreachable')
            else:
                for ips in responseIPs:
                    data = (gmttime, src, dst, dnsID, foundDomain, ips)
                    #print data
                    add_dns_data(cnx, data, dnsTable)
            if badRequest or serverFailure or portUnreachable:
                #print data
                add_dns_data(cnx, data, dnsTable) # add our data to the database
            del dnsIDDict[dnsID]
            try:
                del orderedDict[dnsID]
                #print 'deleted ' + dnsID
            except:
                #print 'tried to delete ' + dnsID
                if bufferEntry[0] == dnsID:
                    bufferEntry = ('empty', 'empty')
                

'''
This fucntion checks the orderedDict for unanswered requests older than maxTime. 
With the buffered functioning of tshark, with light traffic output will be held
back by tshark and thus appear to be old. On networks with reasonable traffic,
this should not be an issue.
'''
def check_for_old(cnx, maxTime, dnsTable):
    global bufferEntry
    if bufferEntry[0] == 'empty':
        bufferEntry = orderedDict.popitem(last=False) # get the first item in the ordered dict of dnsID's (aka the oldest entry)
    # print bufferEntry
    if Decimal(time.time()) - bufferEntry[1] > maxTime: # the oldest request is older than maxTime
        #try:
        #print str(Decimal(time.time()) - bufferEntry[1])
        dnsData = dnsIDDict[bufferEntry[0]] # get the info about the resquest
        gmttime = dnsData[0] 
        src = dnsData[2]
        dst = dnsData[1]
        domain = dnsData[4]
        data = (gmttime, src, dst, bufferEntry[0], domain, 'No response')
        # print 'time ' + str(Decimal(time.time()) - bufferEntry[1])
        # print data
        # print 'buffer entry: ' + str(bufferEntry[0]) + ' ' + str(bufferEntry[1])
        add_dns_data(cnx, data, dnsTable) # add the data  to the database
        del dnsIDDict[bufferEntry[0]] # get rid of the entry in our dict
        bufferEntry = ('empty', 'empty') # get a new entry next check
        #except:
            #print 'The dnsID ' + bufferEntry[0] + ' is no longer in the dict, must have been found.'
            #bufferEntry = ('empty', 'empty')
    # else:
    #     print time.time()
    #     print str(Decimal(time.time()) - bufferEntry[1])






