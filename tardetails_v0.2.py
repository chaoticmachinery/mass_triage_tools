#!/usr/bin/env python

# Written by Keven Murphy
# Descrition: Simple script to gather the hashes and details of files stored in tar files
#
# Version: 0.2
#
# Notes:
# Lines with a '0' for the hash means that those items were not a file. Hence no hash could be calculated. 

import sys, getopt
import tarfile
import numpy as np 
import hashlib
import csv
import os
#from pathlib import Path

def print_member_info(member):
    print("{}".format(member.name), end ="|")
    print("{}".format(member.size), end ="|")
    print("{}".format(member.mtime), end ="|")
    print("{}".format(member.mode), end ="|")
    print("{}".format(member.uid), end ="|")
    print("{}".format(member.uname), end ="|")
    print("{}".format(member.gid), end ="|")
    print("{}".format(member.gname), end ="|")
    
    
def hashcalc(tarfile,filename,member,hashtype,extract):
    hashtxt = 0
    if member.isfile():
       #tmpfile = tar.extractfile(filename).read()
       #hash = hashlib.md5(tmpfile)
       if hashtype == 'md5':
          hash = hashlib.md5(tarfile.extractfile(filename).read())
       elif hashtype == 'sha1':
          hash = hashlib.sha1(tarfile.extractfile(filename).read())
       elif hashtype == 'sha256':
          hash = hashlib.sha256(tarfile.extractfile(filename).read())
       elif hashtype == 'sha512':
          hash = hashlib.sha512(tarfile.extractfile(filename).read())          
       print(hash.hexdigest(), end ="|")
       hashtxt = hash.hexdigest()
       if extract == 1:
          extractfile(tarfile,filename,member,hashtxt)
    else:
       print('0', end ="|")    

   
def extractfile(tarfile,filename,member,hashtxt):    
    filenamechk = filename +"_"+hashtxt
    if not os.path.isfile(filenamechk):
       tarfile.extract(filename)
       os.rename(filename,filenamechk)

def main(argv):
   tarinfile = ''
   outputfile = ''
   hashtype = 'md5'
   extract = 0
   try:
      opts, args = getopt.getopt(argv,"mshi:o:",["tarfile=","ofile=","sha512","sha256","extract"])
   except getopt.GetoptError:
      print ('test.py -i <tar file> ')
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print ('test.py -i <tar file> -m/-s/--sha256/--sha512 --extract')
         sys.exit()
      elif opt in ("-i", "--tarfile"):
         tarinfile = arg
      elif opt in ("-o", "--ofile"):
         outputfile = arg
      elif opt in ("-m", "--md5"):
         hashtype = "md5"
      elif opt in ("-s", "--sha1"):
         hashtype = "sha1"
      elif opt in ("--sha256"):
         hashtype = "sha256"
      elif opt in ("--sha512"):
         hashtype = "sha512" 
      elif opt in ("--extract"):
         extract = 1            
   print ('Input file:', tarinfile)
   #print ('Output file is "', outputfile)
   
   print("filename|size|Mod Time|Mode|UID|User|GID|Group Name|"+hashtype+"|source file")
   
   tar = tarfile.open(tarinfile, "r:*")
   for filename in tar.getnames():
       member = tar.getmember(name=filename)
       print_member_info(member)      
       hashcalc(tar,filename,member,hashtype,extract)
       print(tarinfile);

   tar.close()
if __name__ == "__main__":
   main(sys.argv[1:])
