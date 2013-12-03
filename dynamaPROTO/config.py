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
    fa = .5
    fb = .7
    fc = .9
    return flush, fa, fb, fc

#this will define what address our dns should resolve to
def networkAdd():
    network_address = str("10.20.30.40")
    return network_address

def tVars():
    ta = .5
    tb = .7
    tc = .9
    return ta, tb, tc
