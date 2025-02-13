#!/usr/bin/env python3

#Version 2
# Written by: Keven Murphy

import sys
import pandas as pd
import sqlite3
import io  # Import StringIO

header = ["EventTime","EventID","Computer","SecurityID","ContextInfo","Payload","ScriptBlockText","Path","Message",
          "CommandLine4688","ParentProcessName4688","NewProcessName4688","Connection6","OperationName81_82",
          "Operation82","ResourceURI82","ErrorCode142","AuthenticationMechanism169","ServiceName7045","ServiceType7045",
          "StartType7045","ImagePath7045","AccountName7045","EventRecordID","Level","Opcode","Task","Channel",
          "OSPath","ClientRunTime","FlowId","ClientId","Fqdn"]

print('Filename converting:', sys.argv[1])
outputfile = sys.argv[1] + '.csv'
print('Output Filename:', outputfile)

readfile = open(sys.argv[1], 'r')
count = -1

while True:
    line = readfile.readline()
    count += 1
    if not line:
        break

    # Wrap line in StringIO to handle it as a file-like object
    df = pd.read_json(io.StringIO(line), orient='records')

    if count > 0:
        df.to_csv(outputfile, columns=header, encoding='utf-8', sep='|', quotechar="~", index=False, header=False, mode='a')
    else:
        df.to_csv(outputfile, columns=header, encoding='utf-8', sep='|', quotechar="~", index=False, header=True, mode='w') 

readfile.close()

print("NOTE: Resulting output file is | delimintated and uses ~ as the field quote.")
