#!/usr/bin/python
###################################################################################################
#  IR Distill
#
#  By: Keven Murphy
#
#  Version: 0.4
#
#  Description: 
#  IR File Distill is designed to help reduce the amount of output that has to be reviewed during
#  mass triage.
#
#  Usage APPCACHE/SHIMCACHE:
#  1) Gather up SYSTEM hives
#  2) Run RegRipper on all system hives. Make sure to use the modified version.
#      Windows: find {directory with SYSTEM hives} -print -exec rip.exe -r {}  -p appcompatcache  ; >> appcache{date}.txt
#      *NIX:    find {directory with SYSTEM hives} -print -exec rip.pl  -r {}  -p appcompatcache \; >> appcache{date}.txt
#  3) grep APPCACHE appcache{date}.txt | cut -d\| -f2 | sort | uniq -c | sort -f -t\| -k2 --ignore-case > {filename}.txt
# 3a) cat appcache{date}.txt | parallel --pipe grep -a "APPCAC" | | cut -d\| -f2 | sort | uniq -c | sort -f -t\| -k2 --ignore-case > {filename}.txt
#  4) ir_distill --sqlite os.sqlite --file {filename}.txt  --out {outputfilename} --ignorecase
#  5) Review output
#
#  Usage AMCACHE:
#  1) Gather up AMCACHE hives
#  2) Run RegRipper on all system hives. Make sure to use the modified version.
#      Windows: find {directory with AMCACHE hives} -print -exec rip.exe -r {}  -p amcache3  ; >> amcache{date}.txt
#      *NIX:    find {directory with AMCACHE hives} -print -exec rip.pl  -r {}  -p amcache3 \; >> amcache{date}.txt
#  3) grep -a "Path:" amcache{date}.txt | cut -d\| -f1 | cut -d" " -f2- | sort | uniq -c | sort -f -t\| -k2 --ignore-case > {filename}.txt
#  cat amcache_051317.txt | parallel --pipe grep -a  "Path:"  > a
#
#  4) ir_distill --sqlite os.sqlite --file {filename}.txt  --out {outputfilename} --ignorecase
#  5) Review output
#
#
#  Pull for ecat
#   grep -a "|km"  kmfile.txt |  cut -d\| -f2 | sed 's/^/C:/g' > amcache_051317_pull.txt
#   cat  shimcache | cut -d\# -f1 |sed 's/ *$//' | cut -d\| -f 2| sed 's/^/C:/g' > s.pull

# Shimcache
# sed 's/ *$//'  remove the end of line blank spaces 
# grep -a APPCAC  system_051317_applines.txt   | fgrep -a -f shimcache_051317_findings.pull | cut -f2,4- | sed 's/Executed//g'|sed 's/\|$//g' | sed 's/||/|/g'   > shimcache_051317_findings.newpull.csv

# Amcache
# grep -a "Path:"
# grep -a "Path:" amcache_051317.txt  | fgrep -a -f 3 | cut -f1,2 -d\| | cut -f3- -d: | sort | uniq > 4
# sed 's/Path: //g' 4 |  sed 's/SHA1: 0000//g' > 5
# ./virustotal-search.py    -o output ./5_hashes

#Create NSRL DB
#1) mv NSRLFile.txt NSRLFile.csv
#2) mv NSRLProd.txt NSRLProd.csv
#3) sqlite3 nsrl.db
#SQLite version 3.22.0 2018-01-22 18:45:57
#Enter ".help" for usage hints.
#4) sqlite> .mode csv
#5) sqlite> .import NSRLFile.csv nsrl
#6) sqlite> .import NSRLProd.csv prod
#7) sqlite> CREATE INDEX `sha1` ON `nsrl` ( `SHA-1` COLLATE NOCASE );
#8) sqlite> CREATE INDEX `code` ON `prod` ( `ProductCode`  COLLATE NOCASE );
#9) sqlite> CREATE INDEX `apptype` ON `prod` ( `ApplicationType`  COLLATE NOCASE );
#10) sqlite> CREATE INDEX `OpSystemCode` ON `prod` ( `OpSystemCode`  COLLATE NOCASE );
#11) sqlite> .exit

#1) Remove non-ascii characters:  perl -i.bak -pe 's/[^[:ascii:]]//g' NSRLFile.txt 
#2) Rename NSRLFile.txt to nsrl.csv
#   Rename NSRLProd.txt to prod.csv
#3) ./test.py -f nsrl.csv -f NSRLMfg.csv -f NSRLOS.csv -f NSRLProd.csv -o ./nsrl.db


#White/Review List Creation
#1) echo 'SHA-1|FileName' > review.csv
#2) grep AmCache  amcache_2019-04-24.txt | awk  -v OFS="\|" -F"\|" '{print $8, $7}' >> review.csv
#3) sqlite3 review.db
#4) sqlite>  .mode csv
#5) sqlite>  .separator "\|"
#6) sqlite> .import review.csv review
#7) sqlite> CREATE INDEX `sha1` ON `review` ( `SHA-1` COLLATE NOCASE );
#8) sqlite> CREATE INDEX `filename`  ON `review` ( `FileName` COLLATE NOCASE );
#9) sqlite> .exit

#White/Review List Append to DB
#1) echo 'SHA-1|FileName' > review.csv
#2) Gather new items for the review/whitelist
#   grep AmCache  amcache_2019-04-24.txt | awk  -v OFS="\|" -F"\|" '{print $8, $7}' >> review.csv
#3) sqlite3 review.db
#4) sqlite>  .mode csv
#5) sqlite>  .separator "\|"
#6) sqlite> .import review.csv review
#7) sqlite> .exit

#ECAT DB Notes
#Note: This is very slow compared to creating and running against a SQLite db of the table
# 1) *NIX must install unixODBC and FreeTDS; make sure to install the devel for both
# 2) pip install pyodbc
# 3) /etc/odbc.ini contents:
#[MSSQLServer]
#Driver = FreeTDS
#Description = Any description
#Trace = No
#Server = xx.xx.xx.xx
#Port = 1433
#Database = ECAT$PRIMARY

#ECAT SQLite Notes
#Note you need to install FreeTDS, unixODBC, and create an /etc/odbc.ini
#1) run dbtocsv.py --server {IP}  --user {User} --pass {Password} --out {output filename}
#2) sqlite3 {db name}.db
#3) sqlite>  .mode csv
#4) sqlite> .import review.csv review
#5) sqlite> CREATE INDEX `sha1` ON `review` ( `SHA-1` COLLATE NOCASE );
#6) sqlite> .exit
###################################################################################################

from __future__ import division
import sys, getopt
import sqlite3 as lite
import os.path
import argparse
import io
import string
import filetype
import pyodbc

def b(hs):
    """Convert a hex string to bytearray
 
    Given a string of an even length, containing
    hexidecimal characters (e.g., 0xAB34F1), convert
    it to an array of bytes (chopping of the 0x)
    
    Source: https://obsoleter.wordpress.com/2012/08/27/pyodbc-and-sql-server-binaryvarbinary-fields/
    """
    try:
        return bytearray([int(c, 16) for c in chunks(hs[2:], 2)])
    except:
        return hs
 
def h(bs):
    """Convert bytearray to hex string
 
    Given a bytearray, convert it to a string of
    an even length, containing the associated
    hexidecimal characters for each byte
    
    Source: https://obsoleter.wordpress.com/2012/08/27/pyodbc-and-sql-server-binaryvarbinary-fields/
    """
    try:
        hs = ["{0:0>2}".format(hex(b)[2:].upper()) for b in bs]
        return '0x' + ''.join(hs)
    except:
        return bs

def nsrllookup(lineimport,writedata):
   # Searches for matches to NSRL SHA1 hashes
   linedata = lineimport.split(None, 1)
   sqlsettings = ' COLLATE NOCASE ' + combinesettings
   
   try: 
      line = linedata[0]
      dataline=[]

      with con:
         con.row_factory = lite.Row
         cur = con.cursor()
         srchline = line.decode("utf8")
         sqlstr = 'SELECT * from nsrl WHERE "SHA-1" = ?' + combinesettings
         cur.execute(sqlstr, (srchline,) )
         row = cur.fetchone()
         if row is None:
            dataline.append(linedata[0].decode("utf8"))
            dataline.append("NSRLEND")
         else: 
            dataline.append(linedata[0].decode("utf8"))
            dataline.append(row["MD5"])
            dataline.append(row["CRC32"])
            dataline.append(row["FileName"])
            dataline.append(row["FileSize"])
            try:
               sqlstr2 = 'SELECT * from prod WHERE ProductCode = ? '  + combinesettings
               cur.execute(sqlstr2, (row["ProductCode"],) )
               rowsprod = cur.fetchone()

               if rowsprod:
                 dataline.append(rowsprod["ApplicationType"])
                 dataline.append(rowsprod["ProductName"])
                 dataline.append(rowsprod["ProductVersion"])  
               
            except Exception as e:
               print("Database Prod table in NSRL db - Error: %s" % e)
               sys.exit(1)
            dataline.append('NSRL')
            writedata=writedata+1;

   except Exception as e:
         print("Database NSRL table in NSRL db - Error: %s" % e)
         sys.exit(1)
         
   return dataline,writedata

def ecatlookup(lineimport,writedata,msdb):
   linedata = lineimport.split(None, 1)

   ecathashsql="""\
   select
         HashSHA1,
         HashMD5,
         FirstSeenFilename,
         Size,
         Description,
         [cn].CompanyName,
     CASE 
        WHEN [mo].BiasStatus = -2 THEN 'Blacklisted'
        WHEN [mo].BiasStatus = 0 THEN 'Neutral'
        WHEN [mo].BiasStatus = 1 THEN 'Graylisted'
        WHEN [mo].BiasStatus = 2 THEN 'Whitelisted'
      END AS Status
        ,CASE 
        WHEN [mo].ModuleHashKnownGood = 1 THEN 'Good'
        WHEN [mo].ModuleHashKnownMalicious = 1 THEN 'Malicious'
                WHEN [mo].ModuleHashKnownSuspicious = 1 THEN 'Suspicious'
                WHEN [mo].ModuleHashUnknown = 1 THEN 'Unknown'
                ELSE 'N/A'
       END AS Reputation
        ,CASE WHEN [mo].IOCLevel0 > 0 THEN 1024 
       ELSE  
            (
             (CASE WHEN [mo].IOCLevel1 > 7 THEN 7 ELSE [mo].IOCLevel1 END) * 128 +
             (CASE WHEN [mo].IOCLevel2 > 15 THEN 15 ELSE [mo].IOCLevel2 END) * 8 +
             (CASE WHEN [mo].IOCLevel3 > 7 THEN 7 ELSE [mo].IOCLevel3 END)
                         ) 
      END AS IIOCScore
          ,AvScanResult
          ,YaraScanResult
          ,*
      FROM [ECAT$PRIMARY].[dbo].uvw_Modules as [mo] WITH(NOLOCK)
          INNER JOIN [ECAT$PRIMARY].[dbo].[CompanyNames] AS [cn] WITH(NOLOCK) ON ([cn].[PK_CompanyNames] = [mo].[FK_CompanyNames])   
      WHERE [mo].HashSHA1 = 0x"""
    
   linedata = lineimport.split(None, 1)
   cursor = msdb.cursor()
   
   try: 
      line = linedata[0]
      dataline=[]
      
      with msdb:
         ecathashsql = ecathashsql + linedata[0]
         #print "\n\n%s" % ecathashsql
         cursor.execute(ecathashsql)

         if 'LIMIT' in showallmatches:
	        list = cursor.fetchone()
         else:
            list = cursor.fetchall()
         if len(list) < 1:
            dataline.append(linedata[0].decode("utf8"))
            dataline.append("NWEdbEnd")
         else:
            for row in list:
               #match.write(u'SHA1|MD5|CRC32|FileName|FileSize|ApplicationType|ProductName|Product Version|DB Source\n')
               #dataline.append(linedata[0].decode("utf8"))
               str0 = h(row[0])
               str1 = h(row[1])
               # remove the 0x from the Hashes
               dataline.append(str0[2:])  #HashSha1
               dataline.append(str1[2:])   #HashMD5               
               #dataline.append(row[0])  #HashSha1
               #dataline.append(row[1])   #HashMD5
               dataline.append("")
               dataline.append(row[2])  #FirstSeeenFileName
               dataline.append(row[3])    #Size
               dataline.append(row[4])   #Description
               dataline.append(row[5])   #CompanyName
               dataline.append("")
               dataline.append("Status: %s" % row[6])   #Status 
               dataline.append("Reputation: %s" % row[7])   #Reputation
               dataline.append("IIOC: %s" % row[8])   #IIOCScore
               dataline.append("AVScanResults: %s" % row[9]) 
               dataline.append("YaraScanResults: %s" % row[10])
               dataline.append("NetWitness_Endpoint") 
               writedata = writedata + 1
   except Exception as e:
         print("MSSQL Database Error: %s" % e)
         sys.exit(1)         
   return dataline,writedata

def nwereviewlookup(lineimport,writedata,reviewlist):
   # Searches for matches to Review/Whitelist SHA1 hashes
   #lineimport=filter(lambda x: x in string.printable, lineimport)
    linedata = lineimport.split(None, 1)
    line = linedata[0]
    dataline=[]
    
    
    for dbitem in reviewlist:
       if os.path.isfile(dbitem):
          reviewcon = lite.connect(dbitem)
       else:
          print "\n\nError: NWE SQLite database does not exist."
          sys.exit(1)   

       try: 
            with reviewcon:
                reviewcon.row_factory = lite.Row
                cur = reviewcon.cursor()
                srchline = line.decode("utf8")
                
                sqlstr = "SELECT * from review WHERE `SHA-1` = '0x"+srchline+"'"+ combinesettings
                
                print("SQL: %s" % sqlstr)
                
                #cur.execute(sqlstr, (srchline,) )
                cur.execute(sqlstr)
                #print ("%s %s" % (sqlstr, srchline))
                row = cur.fetchone()
                
                if row:
                    dataline.append(row["SHA-1"][2:])  #HashSha1
                    dataline.append(row["HashMD5"][2:1])   #HashMD5      
                    dataline.append("")
                    dataline.append(row["FirstSeenFileName"])  #FirstSeeenFileName
                    dataline.append(row["Size"])    #Size
                    dataline.append(row["KnownDescription"])   #Description
                    dataline.append(row["CompanyName"])   #CompanyName
                    dataline.append("")
                    dataline.append("Status: %s" % row["Status"])   #Status 
                    dataline.append("Repuatation: %s" % row["Reputation"])   #Reputation
                    dataline.append("IIOC: %s" % row["IIOCScore2"])   #IIOCScore
                    dataline.append("AVScanResults: %s" % row["AVScanResult"]) 
                    dataline.append("YaraScanResults: %s" % row["YaraScanResult"])
                    src = 'NetWitness_Endpoint %s'  % dbitem
                    dataline.append(src)   
                    writedata=writedata+1;

       except Exception as e:
                if "list index out of range" in e:
                   print("\nBad input data at line %d: %s" % (filelinecnt,lineimport))
                   print("Hash lenght: %d" % len(lineimport))
                   print("Ignoring bad line.\n %s" % e)
                   print("\n\n")
                else:
                   print("Database NWE SQLite table in review/whitelist db - Error: %s" % e)
                   sys.exit(1)
       reviewcon.close()
    if writedata == 0:
       if 'filecheckcon' in globals():
             #print(linedata)
          try: 
              dataline.append(linedata[0].decode("utf8"))
              dataline.append(linedata[1].decode("utf8"))
          except:
              print("\nBad input data at line %d: %s" % (filelinecnt,linedata))
              print("Ignoring bad line.")
              print("\n\n")
       else:
          dataline.append(linedata[0].decode("utf8"))
          dataline.append("EOFIRDISTILL")        
        
    return dataline,writedata


def reviewlookup(lineimport,writedata,reviewlist):
   # Searches for matches to Review/Whitelist SHA1 hashes
   #lineimport=filter(lambda x: x in string.printable, lineimport)
    linedata = lineimport.split(None, 1)
    line = linedata[0]
    dataline=[]
    
    
    for dbitem in reviewlist:
       if os.path.isfile(dbitem):
          reviewcon = lite.connect(dbitem)
       else:
          print "\n\nError: Review/White List SQLite database does not exist."
          sys.exit(1)   

       try: 
            with reviewcon:
                reviewcon.row_factory = lite.Row
                cur = reviewcon.cursor()
                srchline = line.decode("utf8")
                
                if 'filecheckcon' in globals():
                    sqlstr = "SELECT * from review WHERE `FileName` = ? "  + combinesettings
                else:
                    sqlstr = "SELECT * from review WHERE `SHA-1` = ? "  + combinesettings
                
                cur.execute(sqlstr, (srchline,) )
                #print ("%s %s" % (sqlstr, srchline))
                row = cur.fetchone()
                  
                if row:
                    dataline.append(linedata[0].decode("utf8"))
                    dataline.append("")
                    dataline.append("")
                    dataline.append(row["FileName"])
                    dataline.append("")
                    dataline.append("")
                    dataline.append("")  
                    dataline.append("")
                    src = 'Review/Whitelist %s'  % dbitem
                    dataline.append(src)   
                    writedata=writedata+1;

       except Exception as e:
                if "list index out of range" in e:
                   print("\nBad input data at line %d: %s" % (filelinecnt,lineimport))
                   print("Hash lenght: %d" % len(lineimport))
                   print("Ignoring bad line.\n %s" % e)
                   print("\n\n")
                else:
                   print("Database review table in review/whitelist db - Error: %s" % e)
                   sys.exit(1)
       reviewcon.close()
    if writedata == 0:
       if 'filecheckcon' in globals():
             #print(linedata)
          try: 
              dataline.append(linedata[0].decode("utf8"))
              dataline.append(linedata[1].decode("utf8"))
          except:
              print("\nBad input data at line %d: %s" % (filelinecnt,linedata))
              print("Ignoring bad line.")
              print("\n\n")
       else:
          dataline.append(linedata[0].decode("utf8"))
          dataline.append("EOFIRDISTILL")        
        
    return dataline,writedata

def filenamelookup(lineimport,writedata):
   #Make sure there is no control strings
   
   #lineimport=filter(lambda x: x in string.printable, lineimport)
   linedata = lineimport.split(None, 1)

   if (len(linedata) > 1) and (len(linedata[1]) > 2): 
        #print len(linedata[1])       
        #print linedata[1]
        try: 
            line = linedata[1]
            dataline=[]
            with filecheckcon:

                filecheckcon.row_factory = lite.Row
                cur = filecheckcon.cursor()
                srchline = line.decode("utf8")
                sqlstr = "SELECT * from files WHERE `file` = ? "  + combinesettings
                #print sqlstr
                cur.execute(sqlstr, (srchline[2:],) )
            
                rows = cur.fetchall()

                if len(rows)==0:
                    dataline.append(linedata[0].decode("utf8"))
                    dataline.append(linedata[1].decode("utf8"))
                else:  
                    for row in rows:
                       writedata=writedata+1; 
                       dataline.append(linedata[0].decode("utf8"))
                       dataline.append("")
                       dataline.append("")
                       dataline.append("")
                       dataline.append("")
                       dataline.append(row["file"])
                       dataline.append("")
                       dataline.append(row["os"])
                       dataline.append('OS_Distill')

        except Exception as e:
                #print("Database files table in OS Distill db - Error: %s" % e)
                #print("Most likely a bad line in input file.")
                dataline=[]
                #sys.exit(1)
         
        return dataline,writedata
        #return
   else:
       return "",0
       #return
       
def fl_writeout(dataline,datawrite):
    itm = 0
    if datawrite > 0:
       for item in dataline:
          if item.isdigit():
             match.write(u'%s' % item)
          elif item:
             match.write(u'%s%s%s' % (csvquote,item,csvquote)) 
          else: 
             match.write(u'%s' % (item))
          itm=itm+1;
          if itm < len(dataline):
              match.write(u'|')
          if 'OS_Distill' in item:
              match.write(u'\n')
    else:
       for item in dataline:
          if item.isdigit():
             nomatch.write(u'%s' % item)
          elif item:
             nomatch.write(u'%s%s%s' % (csvquote,item,csvquote)) 
          else: 
             nomatch.write(u'%s' % (item))
          itm=itm+1;
          if itm < len(dataline):
             nomatch.write(u'|')
       nomatch.write(u'\n')
    return

def safe_str(obj):
    try: return str(obj)
    except UnicodeEncodeError:
        return obj.encode('ascii', 'ignore').decode('ascii')
    return ""

def writeout(dataline,datawrite):
    itm = 0
    #print("Writeout: %s %s" % (datawrite, dataline))
    
    if datawrite > 0:
       rowcnt=0
       for item in dataline:
          if (safe_str(item).isdigit()):
             match.write(u'%s' % item)
          elif item:
             match.write(u'%s%s%s' % (csvquote,item,csvquote)) 
          else: 
             match.write(u'%s' % (item))
          itm=itm+1;
          if itm < len(dataline):
             match.write(u'|')
          if type(item) is str:
             if ('NSRL' in item) or ('Review/Whitelist' in item) or ('NetWitness_Endpoint' in item):
                match.write(u'\n')
    else:
       try:
          nomatch.write('%s' % dataline[0].decode("utf8"))
          if 'NSRLEND' in dataline[1].decode("utf8"):
              nomatch.write(u'\n')
              return
          if 'EOFIRDISTILL' in dataline[1].decode("utf8"):
              nomatch.write(u'\n')
              return           
          if 'NWEdbEnd' in dataline[1].decode("utf8"):
              nomatch.write(u'\n')
              return 
          nomatch.write(u'|')
          nomatch.write('%s' % dataline[1].decode("utf8"))
          nomatch.write(u'\n')  
       except Exception as e:
          if len(dataline) > 0:
             print("Output Error: %s" % e)  
             print("Dataline len: %s" % len(dataline))
    return

def file_len(fname):
    i=0
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1	 

def main(argv):
   global csvquote
   global ignorecase
   global showallmatches
   global combinesettings
   global nomatch
   global match
   global filelinecnt
   csvquote = '"'    
   inputfile = ''
   outputfile = ''
   sqlitefile = ''
   linecnt = 0
   version = '0.4'

   print("IR Distill")   
   print("A NSRL/Review/Whitelist Comparison Reducer")
   print("By: Keven Murphy")
   print("License: GPL")
   print("Version: %s" % version)
   print("Site: https://github.com/chaoticmachinery/\n")
   
   parser = argparse.ArgumentParser(description="NSRL/Review/Whitelist Comparison Reducer")

   parser.add_argument('-n', '--nsrl', dest='nsrl', help='NSRL SQLite database to check against', required=False)
   parser.add_argument('-f', '--filecheck', dest='filecheck', help='OS Distil SQLite database to check against', required=False)
   parser.add_argument('-i', '--infile', help='Input file', required=True)
   parser.add_argument('-o', '--out', default='output', help='Output the results to filename; creates a OUT_nomatch.txt file', required=True)
   parser.add_argument('--showallmatches', help='Show all OS matches in output; creates a OUT_match.txt file',action="store_true")   
   parser.add_argument('--ignorecase', help='Applys to filename match. Ignore case when doing db lookups. Tool takes longer to run with this option',action="store_true")
   parser.add_argument('-r', '--reviewlist', nargs='*', dest='reviewlist',help='SQLite database(s) of reviewed binaries/whitelist', required=False)

   #NWE MSSQL
   parser.add_argument('-u','--user', help='Username for SQL Database. Default: Windows Credentials', metavar='<user>')
   parser.add_argument('-p','--pass', dest='passwd', help='Password for SQL Database. Default: Windows Credentials', metavar='<password>')
   parser.add_argument('-s','--server', help='Hostname or IP for SQL Server. Default: localhost', metavar='<hostname or IP>', default='LOCALHOST')
   parser.add_argument('-db','--database', help='NWE database', metavar='<database>', default='ECAT$PRIMARY')
   parser.add_argument('--driver', help='FreeTDS Driver', metavar='<driver>', default='FreeTDS')
   #NWE SQLITE
   parser.add_argument('-e','--nwe', nargs='*', dest='nwe',help='NWE SQLite database(s) of reviewed binaries/whitelist', required=False)

   args = parser.parse_args()
   
   print("Input filename: %s" % args.infile)
   print("Output filename: %s" % args.out)
   print("NSRL SQLite filename: %s" % args.nsrl)
   print("Review/White List SQLite filename: %s" % args.reviewlist)
   print("Filename Check SQLite filename: %s" % args.filecheck)
   print("NWE SQLite filename: %s" % args.nwe)
   if args.user:
       print("NetWitness Endpoint Database: %s" % args.database)
       print("NetWitness Endpoint User: %s" % args.user)
       print("NetWitness Endpoint Password: %s" % args.passwd)
       print("NetWitness Endpoint Server: %s" % args.server)
       print("NetWitness Endpoint Driver: %s" % args.driver)
   
   
   proceed = 0;
   if args.filecheck:
       proceed = proceed +1
   if args.nsrl:
       proceed = proceed +1
   if args.reviewlist:
       proceed = proceed +1
   if args.server:
       proceed = proceed +1
   if args.nwe:
       proceed = proceed +1
   if proceed < 1:
       print('No databases were given as arguments!')
       sys.exit(1)
   
   
   ignorecase = ""
   showallmatches = "   LIMIT 1;"
   print("\n")
   if args.ignorecase:
      print("Settings: Tool set to ignorecase.")
      ignorecase = "    COLLATE NOCASE "
   if args.showallmatches:
      print("Settings: All OS matches will be outputed.")
      showallmatches = ""
   combinesettings = ignorecase + ' ' + showallmatches
   #print "\n"
	
   nomatchfilename = args.out + "_nomatch.txt"
   matchfilename = args.out + "_match.csv"
 
   if args.user:
      #Build query to connect to DB
      if args.user and args.passwd:
         #msconn = 'DRIVER={};SERVER={};DATABASE={};UID={};PWD={}'.format('FreeTDS', args.server, args.database, args.user, args.passwd)
         msconn = 'DRIVER='+args.driver+';SERVER='+args.server+';PORT=1433;DATABASE='+args.database+';UID='+args.user+';PWD='+args.passwd+';TDS_Version=8.0;'
      else:
         msconn = 'DRIVER={};SERVER={};DATABASE={};Trusted_Connection=yes'.format('{FreeTDS}', args.server, args.database)
      #Connect to DB
      try:
         msdb = pyodbc.connect(msconn)
         print('MSSQL DB connection success.')
      except pyodbc.Error as err:
         parser.error(err) 
         sys.exit(1)
  
   if args.nsrl:
     if os.path.isfile(args.nsrl):
         global con
         con = lite.connect(args.nsrl)
     else:
         print('\n\nError: NSRL SQLite database does not exist.')
         sys.exit(1)
      
   if args.filecheck:
     if os.path.isfile(args.filecheck):
         global filecheckcon
         filecheckcon = lite.connect(args.filecheck)
     else:
         print('\n\nError: OS Distill SQLite database does not exist.')
         sys.exit(1)

   reviewlistdb = []
   if args.reviewlist:
       for filedir in args.reviewlist:
           if os.path.isfile(filedir):
               reviewlistdb.append(filedir)
           if os.path.isdir(filedir):
               from os import listdir
               from os.path import isfile, join
               onlyfiles = [f for f in listdir(filedir) if isfile(join(filedir, f))]
               #print(onlyfiles)
               for testfile in onlyfiles:
                   checkf = filedir + "/" + testfile
                   kind = filetype.guess(checkf)
                   #print('File MIME type: %s' % kind.mime)
                   if 'application/x-sqlite3' in kind.mime:
                       reviewlistdb.append(checkf)
                       
   nwereviewlistdb = []
   if args.nwe:
       for filedir in args.nwe:
           if os.path.isfile(filedir):
               nwereviewlistdb.append(filedir)
           if os.path.isdir(filedir):
               from os import listdir
               from os.path import isfile, join
               onlyfiles = [f for f in listdir(filedir) if isfile(join(filedir, f))]
               #print(onlyfiles)
               for testfile in onlyfiles:
                   checkf = filedir + "/" + testfile
                   kind = filetype.guess(checkf)
                   #print('File MIME type: %s' % kind.mime)
                   if 'application/x-sqlite3' in kind.mime:
                       nwereviewlistdb.append(checkf)                       

   if not os.path.isfile(args.infile):
      print('\n\nError: Input file %s does not exist.' % args.infile)
      sys.exit(1)      

   nomatch = io.open(nomatchfilename, 'w', encoding='utf-8')
   match = io.open(matchfilename, 'w', encoding='utf-8')
   if args.filecheck:
       match.write(u'Freq. Cnt|SHA1|MD5|CRC32|FileName|FileSize|ApplicationType|ProductName|Product Version|DB Source\n')
       nomatch.write(u'Freq. Cnt|Filename\n')
   else:
       match.write(u'SHA1|MD5|CRC32|FileName|FileSize|ApplicationType|ProductName|Product Version|DB Source\n')
   
   #Number of lines in file
   filelen=file_len(args.infile)
   filelinecnt = 1
   #dataline=[]
   print "\n"
   with open(args.infile, "rU") as fileread:
       for line in fileread:
          dataline=[]
          filelinecnt += 1
          writedata = 0  
              
          complete = float("{0:.2f}".format((filelinecnt /  filelen) * 100))
          print("Total # of Lines: {} Reading Line: {} Complete: {}%\r".format(filelen, filelinecnt, complete)),

          line = ''.join(line.strip())

          #Remove none printable characters
          line=filter(lambda x: x in string.printable, line)
          
          if args.filecheck:
             dataline,writedata = filenamelookup(line,writedata)
             if writedata < 1:
                if args.reviewlist:
                   dataline,writedata = reviewlookup(line,writedata,reviewlistdb)
             fl_writeout(dataline,writedata)
                             
          if (args.nsrl) or (args.reviewlist) or (args.nwe):
             #Filter out lines that are not 41 characters i.e. SHA1 hashes
             #print("line: %d %s" % (len(line),line))
             if len(line)==40:
                if args.nsrl:
                   dataline,writedata = nsrllookup(line,writedata)               
                if (args.showallmatches) or (writedata < 1):
                   #if writedata < 1:
                   if args.reviewlist:
                      dataline,writedata = reviewlookup(line,writedata,reviewlistdb)                 
                if (args.showallmatches) or (writedata < 1):
                   #if writedata < 1:                         
                   if args.nwe:
                      dataline,writedata = nwereviewlookup(line,writedata,nwereviewlistdb)
                
          if args.user:
             if len(line)==40:
                dataline,writedata = ecatlookup(line,writedata,msdb)

          #print "%s" % dataline
          #print "%s" % writedata
          if not args.filecheck:
             writeout(dataline,writedata)     
          
   print("\n\n")
   fileread.close()
   nomatch.close()
   match.close()
   if args.nsrl:
      con.close()
   if args.user:
      msdb.close()

if __name__ == "__main__":
   main(sys.argv[1:])
