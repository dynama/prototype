#this is a configuration file for the network administrator to make changes
#to how the program runs

def nameVars():
    #3 thresholds for the percentage of vowels
    va = .5
    vb = .7
    vc = .9
    #3 thresholds for numbers in domain name
    na = 4
    nb = 6
    nc = 7
    return va, vb, vc, na, nb, nc

def freqVars():
    #variable for flushing the source table
    flush = 50
    #3 thresholds for percent a single source requests a domain name other than ours
    fa = 2
    fb = 5
    fc = 7
    return flush, fa, fb, fc

#this will define what address our dns should resolve to
def networkAdd():
    network_address = str("10.20.30.40")
    return network_address

#thresholds to determine what the threat level for the DNS packet is once analysis is done, 
#based off of the above thresholds and the analysis module's results.
def tVars():
    ta = 1
    tb = 7
    tc = 10
    return ta, tb, tc
