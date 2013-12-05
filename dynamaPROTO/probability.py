import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, add_mal_sites, get_cnx, check_duplicate, add_prob
import string
import re
import config 

ta, tb, tc = config.tVars()

def getprob():
    global ta, tb, tc
    cnx = get_cnx()
    #get an entry from sketchy sources
    sketchData =get_data(cnx, "SELECT * FROM sketchySources")
    for item in sketchData:
	sqlID = str(item[0])
	sketchThreat = int(item[4])
	malData =get_data(cnx, "SELECT * FROM malSites WHERE sqlID = '"+sqlID+"'")
	if len(malData) != 0:
		malThreat = int(malData[0][4])
		totalThreat = malThreat + sketchThreat
		if totalThreat > tc :
            		probability = 'high'
       		elif totalThreat > tb:
            		probability = 'medium'
        	elif totalThreat > ta:
            		probability = 'low'
        	else:
            		probability = 'no'
		tempList = [item[0],item[1],item[2], item[3],probability]
		if probability != 'no':
			try:
				add_prob(cnx,tempList)
			except:
				pass
	elif len(malData) == 0:
		if sketchThreat < ta:
			probability = 'no'		
		elif sketchThreat >= ta and totalThreat < tb:
            		probability = 'low'
       		elif sketchThreat >= tb and totalThreat < tc:
            		probability = 'medium'
        	elif sketchThreat >= tc:
            		probability = 'high'
        	else:
            		probability = 'no'
		tempList = [item[0],item[1],item[2], item[3],probability]
		if probability != 'no':
			try:
				add_prob(cnx,tempList)
			except:
				pass
    malDataWhole = get_data(cnx, "SELECT * FROM malSites")
    for item2 in malDataWhole:
	sqlID2 = str(item2[0])
	malSoleThreat = int(item2[4])
	sketchDataPartial = get_data(cnx, "SELECT * FROM sketchySources WHERE sqlID = '"+sqlID2+"'")
	if len(sketchDataPartial) == 0:
		if malSoleThreat < ta:
			probability = 'no'
		elif malSoleThreat >= ta and totalThreat < tb:
            		probability = 'low'
       		elif malSoleThreat >= tb and totalThreat < tc:
            		probability = 'medium'
        	elif malSoleThreat >= tc:
            		probability = 'high'
        	else:
            		probability = 'no'
		tempList = [item2[0],item2[1],item2[2], item2[3],probability]
		if probability != 'no':
			try:
				add_prob(cnx,tempList)
			except:
				pass
	

    #check for equivalent entry in malSites
    #if equivalent exists, add threat together, otherwise use single threat
    #check malsites, if no entry in sketchy sources as well, input into threat prob
    #get all entries from malSites with same sqlID as in sketchySources
#    data = get_data(cnx, "SELECT * FROM malSites INNER JOIN sketchySources ON malSites.sqlID = sketchySources.sqlID")
    #just the level field
#    for item in data:
#	print item[5]
    #get level field from sketchySources with same sqlID
#    data2 = get_data(cnx, "SELECT sketchySources.level FROM sketchySources INNER JOIN sketchySources ON mal_sites.sqlID = sketchySources.sqlID")
    #Create dictionary from the two levels retrieved
#    thedict= dict(zip(data1, data2))
    #for each dictionary entry the key is level from nameBasedAnalysis and value is from frequencyBasedAnalysis
#    for item in thedict:
        #get them as integers
#        nprob = int(item)
#        fprob = int(thedict[item])
        #add levels together for a probability set in config file
#        tprob = nprob + fprob
#        if tprob > ta:
#            probability = 'low'
#        elif tprob > tb:
#            probability = 'medium'
#        elif tprob > tc:
#            probability = 'high'
#        else:
#            probability = 'no'
        #if it reaches any threshold add it to the threat table
#        if probability != 'no':
#            info = data[:5]
#            add_prob(cnx, info, probability)

getprob()
            
        
        

        
