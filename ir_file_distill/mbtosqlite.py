#!/usr/bin/env python


import csv
import sqlite3
import argparse
import sys
from pathlib import Path
import subprocess


def main(argv):
   version = '0.1'
   
   print('Malware Bazaar CSV to SQLite db')
   print('By: Keven Murphy')
   print("License: GPL")
   print("Version: %s" % version)
   print("Site: https://github.com/chaoticmachinery/\n")   
   
   parser = argparse.ArgumentParser(description="Malware Bazaar CSV to SQLite db")

   parser.add_argument('-i', '--incsv', help='Input CSV file', required=True)
   parser.add_argument('-o', '--outdb', default='output', help='SQLite database filename', required=True)
   
   args = parser.parse_args()
   
   print("Input CSV filename: %s" % args.incsv)
   print("Output SQLite DB filename: %s" % args.outdb)
   
   connection = sqlite3.connect(args.outdb)
   cursor = connection.cursor()


   create_table = '''CREATE TABLE "malware"(
        "first_seen_utc" TEXT,
        "sha256_hash" TEXT,
        "md5_hash" TEXT,
        "SHA-1" TEXT,
        "reporter" TEXT,
        "FileName" TEXT,
        "file_type_guess" TEXT,
        "mime_type" TEXT,
        "signature" TEXT,
        "clamav" TEXT,
        "vtpercent" TEXT,
        "imphash" TEXT,
        "ssdeep" TEXT,
        "tlsh" TEXT
   )'''
   cursor.execute(create_table)


   create_fn_index = '''CREATE INDEX `filename`  ON `malware` ( `FileName` COLLATE NOCASE )'''
   cursor.execute(create_fn_index)
   create_sha1_index = '''CREATE INDEX `sha1` ON `malware`  ( `SHA-1` COLLATE NOCASE )'''
   cursor.execute(create_sha1_index)

#   file = open(args.incsv)
#   contents = csv.reader(file)

#   insert_records = '''INSERT INTO malware ("first_seen_utc","sha256_hash","md5_hash","SHA-1","reporter","FileName","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh","odd") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
   #     "first_seen_utc","sha256_hash","md5_hash","SHA-1",
   #     "reporter","FileName","file_type_guess","mime_type",
   #     "signature","clamav","vtpercent","imphash","ssdeep","tlsh"
   #     "first_seen_utc","sha256_hash","md5_hash","SHA-1",    "reporter","FileName","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"
   #first_seen_utc,sha256_hash,md5_hash,SHA-1,reporter,FileName,file_type_guess,mime_type,  signature,clamav,vtpercent,imphash,ssdeep,tlsh
   #?,?,?,?,?,?,?,?,?,?,?,?,?,?

#   cursor.executemany(insert_records, contents)

   #pandas.read_csv(args.incsv).to_sql('malware', conn, if_exists='append', index=False)


   connection.commit()
   connection.close()

   db_name = Path(args.outdb).resolve()
   csv_file = Path(args.incsv).resolve()
   result = subprocess.run(['sqlite3',
                str(db_name),
                '-cmd',
                '.mode csv',
                '.import --skip 9 ' + str(csv_file) + ' malware'], capture_output=True)
   #print(result)



if __name__ == "__main__":
   main(sys.argv[1:])
