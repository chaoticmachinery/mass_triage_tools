#!/usr/bin/python

###################################################################################################
#  IR File Distill
#
#  By: Keven Murphy
#
#  Version: 0.1
#
#  Description: 
#  IR File Distill is designed to help reduce the amount of output that has to be reviewed during
#  mass triage.
#
#  Usage:
#  1) Gather up SYSTEM hives
#  2) Run RegRipper on all system hives. Make sure to use the modified version.
#  3) grep APPCACHE $1 | cut -d: -f2- | sort -t\| -nk2 | cut -d\| -f1 | uniq -c -i | tee app_uniq_$1.txt
#     grep APPCACHE appcache1130.txt | cut -d: -f 2-  |cut -d\| -f1 | sort | uniq -c | sort -h > /mnt/truecrypt6/shimcache/zzzkm.txt
#  4) ir_distill --sqlite os.sqlite --file app_uniq_f0.txt  --out outputfile --ignorecase
#  5) Review output
#
###################################################################################################

from __future__ import division
import sys, getopt
import sqlite3 as lite
import os.path
import argparse
import io

def lookup(lineimport):
   linedata = lineimport.split(None, 1)
   line = linedata[1]
   with con:

      con.row_factory = lite.Row
      cur = con.cursor()
      #sqlline = "SELECT * from files WHERE files = "+line
      srchline = line.decode("utf8")
      #print "Searching for: %s" % srchline[2:]
        
      #cur.execute("SELECT * from files WHERE file = ? " +ignorecase +showallmatches, (srchline[2:],) )
      #sqlstr = "SELECT * from files WHERE file = ? " + " COLLATE NOCASE   LIMIT 1;"
      sqlstr = "SELECT * from files WHERE file = ? "  + combinesettings
      #print 'SQL: %s' % sqlstr   #SELECT * from files WHERE file = ? COLLATE NOCASE LIMIT 1
      #cur.execute("SELECT * from files WHERE file = ? " + combinesettings, (srchline[2:],) )
      cur.execute(sqlstr, (srchline[2:],) )
      
      rows = cur.fetchall()
      if len(rows)==0: 
        nomatch.write(linedata[0].decode("utf8"))
        nomatch.write(u"|")
        nomatch.write(srchline[2:])
        nomatch.write(u'\n')

      #if showallmatches==0:
      for row in rows:
           match.write(linedata[0].decode("utf8"))
           match.write(u"|")
           match.write('\"%s\"|\"%s\"' % (row["file"], row["os"]))
           match.write(u'\n')
      #else:
           #row = rows[0]
           #match.write('\"%s\",\"%s\"' % (row[0],row [1]))
           #match.write(u'\n')
   return
   
def file_len(fname):
    i=0
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1	 

def main(argv):
   inputfile = ''
   outputfile = ''
   sqlitefile = ''
   #global linecnt
   linecnt = 0
   version = '0.1'
   
   print("IR Path/Filename Comparison Reducer")
   print("By: Keven Murphy")
   print("License: GPL")
   print("Version: %s" % version)
   print("Site: https://github.com/chaoticmachinery/fate")
   
   parser = argparse.ArgumentParser(description="An argparse example")

   parser.add_argument('-d', '--sqlite', help='SQLite database to check against', required=True)
   parser.add_argument('-i', '--file', help='Input file', required=True)
   parser.add_argument('-o', '--out', default='output', help='Out results filename', required=True)
   parser.add_argument('--showallmatches', help='Show all OS matches in output',action="store_true")   
   parser.add_argument('--ignorecase', help='Ignore case when doing db lookups. Tool takes longer to run with this option',action="store_true")

   args = parser.parse_args()
   
   	 
   print 'Input filename: ', args.file
   print 'Output filename: ', args.out
   print 'SQLite filename: ', args.sqlite
   
   global ignorecase
   global showallmatches
   global combinesettings
   ignorecase = ""
   showallmatches = "   LIMIT 1;"
   if args.ignorecase:
      print "Setings: Tool set to ignorecase."
      ignorecase = "    COLLATE NOCASE "
   if args.showallmatches:
      print "Settings: All OS matches will be outputed."
      showallmatches = ""
   combinesettings = ignorecase + ' ' + showallmatches
   print "\n"
	
   nomatchfilename = args.out + "_nomatch.txt"
   matchfilename = args.out + "_match.txt"
   
   if os.path.isfile(args.sqlite):
      global con
      con = lite.connect(args.sqlite)
   else:
      print "\n\nError: SQLite database does not exist."
      sys.exit(1)
   if not os.path.isfile(args.file):
      print "\n\nError: Input file %s does not exist." % args.file
      sys.exit(1)      
   
   global nomatch
   global match
   nomatch = io.open(nomatchfilename, 'w', encoding='utf-8')
   match = io.open(matchfilename, 'w', encoding='utf-8')   
   
   #Number of lines in file
   filelen=file_len(args.file)
   filelinecnt = 0
   with open(args.file, "rU") as fileread:
       for line in fileread:
          filelinecnt += 1
          line = ''.join(line.strip())
          #print line
          #linedata = line.split(None, 1)
          #print linedata[1]
          lookup(line)
          complete = float("{0:.2f}".format((filelinecnt /  filelen) * 100))
          print("Total # of Lines: {} Reading Line: {} Complete: {}%\r".format(filelen, filelinecnt, complete)),
   fileread.close()
   nomatch.close()
   match.close()
   con.close()

if __name__ == "__main__":
   main(sys.argv[1:])
