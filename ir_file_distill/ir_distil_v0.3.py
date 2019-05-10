#!/usr/bin/python
###################################################################################################
#  IR Distill
#
#  By: Keven Murphy
#
#  Version: 0.3
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
###################################################################################################

from __future__ import division
import sys, getopt
import sqlite3 as lite
import os.path
import argparse
import io
import string
import filetype

def nsrllookup(lineimport,writedata):
   # Searches for matches to NSRL SHA1 hashes
   linedata = lineimport.split(None, 1)
   
   try: 
      line = linedata[0]
      dataline=[]
      
      with con:
         con.row_factory = lite.Row
         cur = con.cursor()
         srchline = line.decode("utf8")
         sqlstr = "SELECT * from nsrl WHERE `SHA-1` = ? "  + combinesettings
         
         cur.execute(sqlstr, (srchline,) )
         row = cur.fetchone()
         
         if row is None:
            dataline = [linedata[0].decode("utf8")]
         else: 
            dataline.append(linedata[0].decode("utf8"))
            dataline.append(row["MD5"])
            dataline.append(row["CRC32"])
            dataline.append(row["FileName"])
            dataline.append(row["FileSize"])
            try:
               sqlstr2 = "SELECT * from prod WHERE `ProductCode` = ? "  + combinesettings
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

def writeout(dataline,datawrite):
    itm = 0
    #print("Writeout: %s" % dataline)
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
          if ('NSRL' in item) or ('Review/Whitelist' in item):
              match.write(u'\n')
    else:
       try:
          nomatch.write('%s' % dataline[0].decode("utf8"))
          if 'EOFIRDISTILL' not in dataline[1].decode("utf8"):
             nomatch.write(u'|')
             nomatch.write('%s' % dataline[1].decode("utf8"))
          nomatch.write(u'\n')  
       except:
          print("bad data")
          
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
   #global con
   #global reviewcon
   #global filecheckcon
   csvquote = '"'    
   inputfile = ''
   outputfile = ''
   sqlitefile = ''
   #global linecnt
   linecnt = 0
   version = '0.3'

   print("IR Distill")   
   print("A NSRL/Review/Whitelist Comparison Reducer")
   print("By: Keven Murphy")
   print("License: GPL")
   print("Version: %s" % version)
   print("Site: https://github.com/chaoticmachinery/")
   
   parser = argparse.ArgumentParser(description="NSRL/Review/Whitelist Comparison Reducer")

   parser.add_argument('-n', '--nsrl', dest='nsrl', help='NSRL SQLite database to check against', required=False)
   parser.add_argument('-f', '--filecheck', dest='filecheck', help='OS Distil SQLite database to check against', required=False)
   parser.add_argument('-i', '--infile', help='Input file', required=True)
   parser.add_argument('-o', '--out', default='output', help='Output the results to filename; creates a OUT_nomatch.txt file', required=True)
   parser.add_argument('--showallmatches', help='Show all OS matches in output; creates a OUT_match.txt file',action="store_true")   
   parser.add_argument('--ignorecase', help='Ignore case when doing db lookups. Tool takes longer to run with this option',action="store_true")
   parser.add_argument('-r', '--reviewlist', nargs='*', dest='reviewlist',help='SQLite database(s) of reviewed binaries/whitelist', required=False)

   args = parser.parse_args()
   
   print 'Input filename: ', args.infile
   print 'Output filename: ', args.out
   print 'NSRL SQLite filename: ', args.nsrl
   print 'Review/White List SQLite filename: ', args.reviewlist
   print 'Filename Check SQLite filename: ', args.filecheck
   
   if not args.filecheck:
       if not args.nsrl:
           if not args.reviewlist:
              print "No SQLite db defined!"
              sys.exit(1)
   
   ignorecase = ""
   showallmatches = "   LIMIT 1;"
   if args.ignorecase:
      print "Settings: Tool set to ignorecase."
      ignorecase = "    COLLATE NOCASE "
   if args.showallmatches:
      print "Settings: All OS matches will be outputed."
      showallmatches = ""
   combinesettings = ignorecase + ' ' + showallmatches
   print "\n"
	
   nomatchfilename = args.out + "_nomatch.txt"
   matchfilename = args.out + "_match.csv"
   
   if args.nsrl:
     if os.path.isfile(args.nsrl):
         global con
         con = lite.connect(args.nsrl)
     else:
         print "\n\nError: NSRL SQLite database does not exist."
         sys.exit(1)
      
   if args.filecheck:
     if os.path.isfile(args.filecheck):
         global filecheckcon
         filecheckcon = lite.connect(args.filecheck)
     else:
         print "\n\nError: OS Distill SQLite database does not exist."
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

   if not os.path.isfile(args.infile):
      print "\n\nError: Input file %s does not exist." % args.infile
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
   filelinecnt = 0
   dataline=[]
   with open(args.infile, "rU") as fileread:
       for line in fileread:
          filelinecnt += 1
          line = ''.join(line.strip())
          writedata = 0  
          #Remove none printable characters
          line=filter(lambda x: x in string.printable, line)
          
          if args.filecheck:
             dataline,writedata = filenamelookup(line,writedata)
             if writedata < 1:
                if args.reviewlist:
                   dataline,writedata = reviewlookup(line,writedata,reviewlistdb)
             fl_writeout(dataline,writedata)
                
          if (args.nsrl) or (args.reviewlist):
             #Filter out lines that are not 41 characters i.e. SHA1 hashes
             #Rember arrays begin with 0
             #print("line: %d %s" % (len(line),line))
             if len(line)==40:
                if args.nsrl:
                   dataline,writedata = nsrllookup(line,writedata)
                if writedata < 1:
                   if args.reviewlist:
                      dataline,writedata = reviewlookup(line,writedata,reviewlistdb)
                writeout(dataline,writedata)
          complete = float("{0:.2f}".format((filelinecnt /  filelen) * 100))
          print("Total # of Lines: {} Reading Line: {} Complete: {}%\r".format(filelen, filelinecnt, complete)),
   print("\n\n")
   fileread.close()
   nomatch.close()
   match.close()
   if args.nsrl:
      con.close()

if __name__ == "__main__":
   main(sys.argv[1:])
