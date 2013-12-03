##global x
##x = 0
##
##def go():
##    global x
##    x = 1
##    
##
##go()
##print x
import config 
global network_address
network_address = '10.20.30.40'
global flush, threshold
flush, threshold = config.freqVars()
global count
count = 0

print flush
print "threshold = ", threshold
