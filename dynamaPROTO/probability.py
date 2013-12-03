import mysql.connector
from mysql.connector import errorcode
from mySQL import get_data, add_mal_sites, get_cnx, check_duplicate
import string
import re
import config 

ta, tb, tc = config.tVars()

def getprob():
    global ta, tb, tc
    cnx = get_cnx()
    #get all entries from malSites with same sqlID as in sketchySources
    data = get_data(cnx, "SELECT * FROM malSites INNER JOIN sketchySources ON malSites.sqlID = sketchySources.sqlID")
    #just the level field
    data1 = data[5]
    #get level field from sketchySources with same sqlID
    data2 = get_data(cnx, "SELECT sketchySources.level FROM sketchySources INNER JOIN sketchySources ON mal_sites.sqlID = sketchySources.sqlID")
    #Create dictionary from the two levels retrieved
    thedict= dict(zip(data1, data2))
    #for each dictionary entry the key is level from nameBasedAnalysis and value is from frequencyBasedAnalysis
    for item in thedict:
        #get them as integers
        nprob = int(item)
        fprob = int(thedict[item])
        #add levels together for a probability set in config file
        tprob = nprob + fprob
        if tprob > ta:
            probability = 'low'
        elif tprob > tb:
            probability = 'medium'
        elif tprob > tc:
            probability = 'high'
        else:
            probability = 'no'
        #if it reaches any threshold add it to the threat table
        if probability != 'no':
            info = data[:5]
            add_prob(cnx, info, probability)

getprob()
            
        
        

        
