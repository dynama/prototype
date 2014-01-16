import mysql.connector
from mysql.connector import errorcode

#This module creates the database that the information of the DNS Packets is stored in.
#It also creates the funstions that are used to insert data into the MtSQL database.
# Mostly from: http://dev.mysql.com/doc/connector-python/en/myconnpy_example_ddl.html

#This function creates the database from the dynama program. It sets up the different tables, and establishes the connection, username/password for the program to communicate to the table to insert/call data.
def initialize_database():	
    cnx = mysql.connector.connect(user='root', passwd='password')
    cursor = cnx.cursor()
    DB_NAME = 'dynama'
    TABLES = {}
    TABLES['dnsPackets'] = (
        "CREATE TABLE `dnsPackets` ("
        "  `sqlID` int(11) NOT NULL AUTO_INCREMENT,"
        "  `datetime` TEXT NOT NULL,"
        "  `src` TEXT NOT NULL,"
        "  `dst` TEXT NOT NULL,"
        "  `dnsID` TEXT NOT NULL,"
        "  `domain` TEXT NOT NULL,"
        "  `ip` TEXT NOT NULL,"
        "  PRIMARY KEY (`sqlID`)"
        ") ENGINE=InnoDB")
    TABLES['dnsPackets2'] = (
        "CREATE TABLE `dnsPackets2` ("
        "  `sqlID` int(11) NOT NULL AUTO_INCREMENT,"
        "  `datetime` TEXT NOT NULL,"
        "  `src` TEXT NOT NULL,"
        "  `dst` TEXT NOT NULL,"
        "  `dnsID` TEXT NOT NULL,"
        "  `domain` TEXT NOT NULL,"
        "  `ip` TEXT NOT NULL,"
        "  PRIMARY KEY (`sqlID`)"
        ") ENGINE=InnoDB")
    TABLES['dstAnalysis'] = (
	"CREATE TABLE `dstAnalysis` ("
	"  `sqlID` int(11) NOT NULL AUTO_INCREMENT,"
	" `domain` TEXT NOT NULL,"
    	"  `dstPercent` FLOAT NOT NULL,"
    	"  `dst_Domain` TEXT NOT NULL,"
    	"  PRIMARY KEY (`sqlID`)"
    	") ENGINE=InnoDB")
    TABLES['srcAnalysis'] = (
	"CREATE TABLE `srcAnalysis` ("
	"  `sqlID` int(11) NOT NULL AUTO_INCREMENT,"
    	"  `src` TEXT NOT NULL,"
    	"  `srcPercent` FLOAT NOT NULL,"
    	"  PRIMARY KEY (`sqlID`)"
    	") ENGINE=InnoDB")
    TABLES['sketchySources'] = (
    "CREATE TABLE `sketchySources` ("
        "  `sqlID` int(11) NOT NULL AUTO_INCREMENT,"
        "  `domain` TEXT NOT NULL,"
        "  `ip` TEXT NOT NULL,"
        "  `src` TEXT NOT NULL,"
        "  `level` TEXT NOT NULL,"
        "  PRIMARY KEY (`sqlID`)"
        ") ENGINE=InnoDB")
    TABLES['sourceTable'] = (
    "CREATE TABLE `sourceTable` ("
        "  `sqlID` int(11) NOT NULL AUTO_INCREMENT,"
        "  `source` TEXT NOT NULL,"
        "  PRIMARY KEY (`sqlID`)"
        ") ENGINE=InnoDB")
    TABLES['sketchyByDomain'] = (
    "CREATE TABLE `sketchySourcesByDomain` ("
        "  `sqlID` int(11) NOT NULL AUTO_INCREMENT,"
        "  `src` TEXT NOT NULL,"
        "  PRIMARY KEY (`sqlID`)"
        ") ENGINE=InnoDB")
    TABLES['malSites'] = (
	" CREATE TABLE `malSites` ("
	"  `sqlID` int(11) NOT NULL AUTO_INCREMENT,"
	"  `domain` TEXT NOT NULL,"
	" `ip` TEXT NOT NULL,"
	" `src` TEXT NOT NULL,"
        " `level` TEXT NOT NULL,"
	"  PRIMARY KEY (`sqlID`)"
	") ENGINE=InnoDB")
    TABLES['threatProb'] = (
        " CREATE TABLE `threatProb` ("
	"  `sqlID` int(11) NOT NULL AUTO_INCREMENT,"
	"  `domain` TEXT NOT NULL,"
	" `ip` TEXT NOT NULL,"
	" `src` TEXT NOT NULL,"
        " `prob` TEXT NOT NULL,"
	"  PRIMARY KEY (`sqlID`)"
	") ENGINE=InnoDB")
    TABLES['region'] = (
	" CREATE TABLE `region` ("
	" `sqlID` int(11) NOT NULL AUTO_INCREMENT,"
	" `ip` TEXT NOT NULL, "
	" `country` TEXT NOT NULL,"
	" PRIMARY KEY (`sqlID`)"
	") ENGINE=InnoDB")
    TABLES['regionAnalysis'] = (
	" CREATE TABLE `regionAnalysis` ("
	" `sqlID` int(11) NOT NULL AUTO_INCREMENT,"
	" `country` TEXT NOT NULL, "
	" `frequency_today` TEXT NOT NULL,"
	" `frequency_hour` TEXT NOT NULL,"
	" `frequency_lastSess` TEXT NOT NULL,"
	" `overall` TEXT NOT NULL,"
	" PRIMARY KEY (`sqlID`)"
	") ENGINE=InnoDB")
    TABLES['multipleReturnIPs'] = (
    " CREATE TABLE `multipleReturnIPs` ("
    " `sqlID` int(11) NOT NULL AUTO_INCREMENT,"
    " `datetime` TEXT NOT NULL, "
    " `src` TEXT NOT NULL,"
    " `domain` TEXT NOT NULL,"
    " `numIPs` TEXT NOT NULL,"
    " PRIMARY KEY (`sqlID`)"
    ") ENGINE=InnoDB")
    TABLES['malHosts'] = (
	" CREATE TABLE `malHosts` ("
	"`sqlID` int(11) NOT NULL AUTO_INCREMENT,"
	"`src` VARCHAR(15) NOT NULL,"
	"`high_number_count_in_name` TEXT NOT NULL,"
	"`high_amount_of_ips_per_domain` TEXT NOT NULL,"
    "`sketchy_src` TEXT NOT NULL,"
    "`sketchy_browse` TEXT NOT NULL,"
	"`total_number_of_flags` INT NOT NULL,"
	"PRIMARY KEY (`sqlID`),"
    "UNIQUE KEY `UNIQ_SRC` (`src`)"
	") ENGINE=InnoDB")
    


    def create_database(cursor):
        try:
            cursor.execute(
                "CREATE DATABASE {} DEFAULT CHARACTER SET 'utf8'".format(DB_NAME))
        except mysql.connector.Error as err:
            print("Failed creating database: {}".format(err))

    create_database(cursor)

    try:
        cnx.database = DB_NAME    
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_BAD_DB_ERROR:
            create_database(cursor)
            cnx.database = DB_NAME
        else:
            print(err)
            exit(1)

    for name, ddl in TABLES.iteritems():
        try:
            print("Creating table {} :".format(name)),
            cursor.execute(ddl)
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_TABLE_EXISTS_ERROR:
                print("already exists.")
            else:
                print(err.msg)
        else:
            print("OK")

    return cursor, cnx


def check_duplicate(cnx,table,domain_id,name):
    cursor = cnx.cursor()
    check_dup = ("SELECT count(*) AS dup FROM %s WHERE %s = %s")
    data = (table, domain_id, name)
    cursor.execute(check_dup,data)
    result = cursor.fetchone()
    return result



#The below functions are set up in this module for the use of the rest of the modules of dynama. They serve to allow the other modules to insert or pull data to/from the database that is captured by dynama. This allows the modules the ability to analyze the data collected in the database to help determine if the DNS packet is potentially malware.
#Returns a list of Tuples from the given SQL Statement
def get_data(cnx, sqlString):
    cursor = cnx.cursor()
    cursor.execute(sqlString)
    result = cursor.fetchall()
    return result

def add_dns_data(cnx, data, dnsTable):
    cursor = cnx.cursor()
    # From: http://dev.mysql.com/doc/connector-python/en/myconnpy_example_cursor_transaction.html
    addDNS = ("INSERT INTO " + dnsTable + " "
                   "(datetime, src, dst, dnsID, domain, ip) "
                   "VALUES (%s, %s, %s, %s, %s, %s)")
    cursor.execute(addDNS, data)
    cnx.commit()

def truncate_table(cnx, tableToTruncate):
    cursor = cnx.cursor()
    truncateString = "TRUNCATE " + tableToTruncate
    cursor.execute(truncateString)
    cnx.commit()

def add_mal_hosts(cnx, data):
    cursor = cnx.cursor()
    addMal = ("INSERT INTO malHosts "
		  "(src, high_number_count_in_name, high_amount_of_ips_per_domain, total_number_of_flags)"
		  "VALUES (%s, %s,%s,%s)")
    cursor.execute(addMal, data)
    cnx.commit()

def add_mal_sites(cnx, data):
    cursor = cnx.cursor()
    addMal = ("INSERT INTO malSites "
	 	  "(sqlID, domain, src, ip, level) "
		  "VALUES (%s, %s, %s, %s, %s)")
    cursor.execute(addMal, data)
    cnx.commit()
def add_prob(cnx, data):
    cursor = cnx.cursor()
    addProb = ("INSERT INTO threatProb "
                   "(sqlID, domain, ip, src, prob) "
                   "VALUES (%s, %s, %s, %s, %s)")
    cursor.execute(addProb, data)
    cnx.commit()

def add_src_data(cnx, data):
    cursor = cnx.cursor()
    addDNS = ("INSERT INTO srcAnalysis "
                    "(src, srcPercent) "
                   "VALUES (%s, %s)")
    cursor.execute(addDNS, data)
    cnx.commit()

def add_dst_data(cnx, data):
    cursor = cnx.cursor()
    addDNS = ("INSERT INTO dstAnalysis "
                   "(dst, dstPercent) "
                   "VALUES (%s, %s)")
    cursor.execute(addDNS, data)
    cnx.commit()

def add_reg_data(cnx, data):
    cursor = cnx.cursor()
    addReg = ("INSERT INTO region "
		  "(ip, country) "
		  "VALUES (%s, %s)")
    cursor.execute(addReg, data)
    cnx.commit()

def add_regAna_data(cnx,data):
    cursor = cnx.cursor()
    addRA = ("INSERT INTO regionAnalysis "
		  "(country, frequency_today, frequency_hour, frequency_lastSess, overall) "
 		  "VALUES (%s, %s, %s, %s, %s)")
    cursor.execute(addRA, data)
    cnx.commit()

def add_multipleReturnIP_data(cnx,data):
    cursor = cnx.cursor()
    addData = ("INSERT INTO multipleReturnIPs "
          "(datetime, src, domain, numIPs) "
          "VALUES (%s, %s, %s, %s)")
    cursor.execute(addData, data)
    cnx.commit()


def add_sketch_sources(cnx, data):
    cursor = cnx.cursor()
    add_sketch_source = ("INSERT INTO sketchySources "
				"(sqlID, domain, ip, src, level) "
				"VALUES (%s, %s, %s, %s, %s)")
    cursor.execute(add_sketch_source, data)
    cnx.commit()

def add_source_table(cnx, data):
    cursor = cnx.cursor()
    add_sketch_source = ("INSERT INTO sourceTable "
			"(datetime, src, dst, dnsID, domain, ip) "
                   	"VALUES (%s, %s, %s, %s, %s, %s)")
    cursor.execute(add_sketch_source, data)
    cnx.commit






def add_data(cnx, data):
    print 'add_data() is deprecated, use add_dns_data'
    add_dns_data(cnx, data)

def get_cnx():
    cnx = mysql.connector.connect(user='root',passwd='password',host='127.0.0.1',database='dynama')
    return cnx

def update_mal_hosts(cnx,src,flag,yesnonos):
    cursor = cnx.cursor()
    if len(src) > 1:
        sqlString = 'INSERT INTO malHosts (src, high_number_count_in_name, high_amount_of_ips_per_domain, sketchy_src, sketchy_browse, total_number_of_flags) \
        VALUES ("' + src + '",' + yesnonos + ",1) ON DUPLICATE KEY UPDATE \
        total_number_of_flags=IF((total_number_of_flags < 4 AND " + flag + "='No'), total_number_of_flags+1, total_number_of_flags), " +  flag + "='Yes'"
        cursor.execute(sqlString)
        cnx.commit()


#INSERT INTO malHosts (src, high_number_count_in_name, high_amount_of_ips_per_domain, sketchy_src, sketchy_browse, total_number_of_flags)          VALUES ("224.0.0.251","No","No","Yes","No",1) ON DUPLICATE KEY UPDATE total_number_of_flags=IF((total_number_of_flags < 4 AND sketchy_src='No'), total_number_of_flags+1, total_number_of_flags), sketchy_src='Yes';
