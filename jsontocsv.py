#!/usr/bin/python3
#
# Converts json to csv
# Written by: Keven Murphy
#
# Version: 0.2
#
# Used with Velociraptor

import sys
import pandas as pd
import sqlite3

print('Filename converting: ', sys.argv[1])
outputfile = sys.argv[1] + '.csv'
print('Output Filename: ', outputfile)
with open(sys.argv[1], encoding='utf-8') as inputfile:
    df = pd.read_json(inputfile, lines = True)

#conn = sqlite3.connect("data.db")
#c = conn.cursor()
headerfull = ["EventTime","EventID","Computer","SecurityID","ContextInfo","Payload","ScriptBlockText","Path","Message","CommandLine4688","ParentProcessName4688","NewProcessName4688","Connection6","OperationName81_82","Operation82","ResourceURI82","ErrorCode142","AuthenticationMechanism169","ServiceName7045","ServiceType7045","StartType7045","ImagePath7045","AccountName7045","EventRecordID","Level","Opcode","Task","Channel","System","EventData","ClientGenTime","FullPath","ClientRunTime","FlowId","ClientId","Fqdn"]

#Stripping out the System and EventData columns as it should be a repeat of whats in the other columns.
header = ["EventTime","EventID","Computer","SecurityID","ContextInfo","Payload","ScriptBlockText","Path","Message","CommandLine4688","ParentProcessName4688","NewProcessName4688","Connection6","OperationName81_82","Operation82","ResourceURI82","ErrorCode142","AuthenticationMechanism169","ServiceName7045","ServiceType7045","StartType7045","ImagePath7045","AccountName7045","EventRecordID","Level","Opcode","Task","Channel","ClientGenTime","FullPath","ClientRunTime","FlowId","ClientId","Fqdn"]

df.to_csv(outputfile, columns = header, encoding='utf-8', sep='|',quotechar = "~",index=False)
print("NOTE: Resulting output file is | delimintated and uses ~ as the field quote.")
#df.to_sql("tablename",conn)


