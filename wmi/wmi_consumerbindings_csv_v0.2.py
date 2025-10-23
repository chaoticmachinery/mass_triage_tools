#!/usr/bin/env python3

#===================================================================================
# Written by: Fireeye Flare Team
# Modified by: Keven Murphy
#
# wmi_consumerbindings_csv.py --path {src directory Repository} --type {win7 or xp}  
#        --verbose
#
#
# --path       Source directory for Repository
# --type       WMI type; Can be either xp or win7
# --verbose    Sends the screen all sorts of output as the script runs
#
#
# Author Notes:
# 1) python-cim is required for the script. Make sure to install github version as
#    the pip install version is hosed.
#
# Mod Log:
#===================================================================================
debug = True
import logging
import sys
import cim
import re
import os.path
import argparse
import io
from cim import CIM
from cim.objects import Namespace

def printStruct(struc, indent=0):
  if isinstance(struc, dict):
    print('  '*indent+'{')
    for key,val in struc.iteritems():
      if isinstance(val, (dict, list, tuple)):
        print('  '*(indent+1) + str(key) + '=> ')
        printStruct(val, indent+2)
      else:
        print('  '*(indent+1) + str(key) + '=> ' + str(val))
    print('  '*indent+'}')
  elif isinstance(struc, list):
    print('  '*indent + '[')
    for item in struc:
      printStruct(item, indent+1)
    print('  '*indent + ']')
  elif isinstance(struc, tuple):
    print('  '*indent + '(')
    for item in struc:
      printStruct(item, indent+1)
    print('  '*indent + ')')
  else: print('  '*indent + str(struc))


def main(argv):
    version = '0.2' 
    badwbem = 0;
    
    parser = argparse.ArgumentParser(description="WMI __filtertoconsumerbinding")

    parser.add_argument('-p', '--path', dest='path', help='Source folder "Repository"', required=True)
    parser.add_argument('-t', '--type', dest='wmitype', help='Can be xp or win7', required=True)
    parser.add_argument('-v', '--verbose', dest='verbose', help='Be verbose', action="store_true")
    parser.add_argument('-o', '--out', default='output', help='Output the results to filename; creates a OUT_nomatch.txt file', required=True)

    args = parser.parse_args()

    if args.verbose:
       print("WMI Search for ConsumerBinding") 
       print("Modified By: Keven Murphy")
       print("License: GPL")
       print("Version: %s" % version)
       print("Site: https://github.com/chaoticmachinery/")
       print("Code is based on: https://github.com/fireeye/flare-wmi/blob/master/python-cim/samples/show_filtertoconsumerbindings.py\n")
       print("Path: %s" % args.path)
       print("Type: %s\n" % args.wmitype)
       print("Output filename: %s" % args.out)
       #print("V: %s" % args.verbose)
    
    if args.wmitype not in ("xp", "win7"):
        raise RuntimeError("Invalid mapping type: {:s}".format(args.wmitype))


    fileout = io.open(args.out, 'a', encoding='utf-8')



    #Output Header
    fileout.write(u"\'EventNamespace\'|\'FilterName\'|\'QueryLanguage\'|\'Query\'|\'Consumer\'|\'CommandLineTemplate\'|\'CreatorSID\'|\'Source File Path\'\n")

    #Namespaces
    #namespaces= ['root\\default','root\\subscription']
    nameclasses= ['__filtertoconsumerbinding','__eventconsumer','__eventfilter']

    c = CIM(args.wmitype, args.path)
    
    repo = cim.CIM.from_path(args.path)
    namespaces = []
    
    def collect(ns):
        for namespace in ns.namespaces:
            namespaces.append(namespace)

        for namespace in ns.namespaces:
            collect(namespace)
    
    with cim.objects.Namespace(repo, cim.objects.ROOT_NAMESPACE_NAME) as root:
        collect(root)

    #printStruct(namespaces)          
    for namespace in namespaces:
        namespacestr = str(namespace)

        if args.verbose:
            print ("\nSearch namespace: %s" % namespacestr)

        try:
            with Namespace(c, namespacestr[1:]) as ns:
                for nameclass in nameclasses: 
                    if args.verbose:
                        print("Checking %s now..." % nameclass)
                    for binding in ns.class_(nameclass).instances:
                    #for binding in ns.class_("__filtertoconsumerbinding").instances:
                        filterref = binding.properties["Filter"].value
                        consumerref = binding.properties["Consumer"].value
                        filter = ns.get(ns.parse_object_path(filterref))
                        consumer = ns.get(ns.parse_object_path(consumerref))

                        #EventNamespace
                        fileout.write(u"\'%s\'" % str(ns))
                        
                        #Filter
                        fileout.write(u"|\'%s\'" % str(filter.properties["Name"].value))
                        
                        #QueryLanguage
                        #Query
                        try:
                            fileout.write(u"|\'%s\'" % str(filter.properties["QueryLanguage"].value))
                            #Need to remove new lines from Query
                            querystr = re.sub(r'[\n\r]+', "", str(filter.properties["Query"].value))
                            fileout.write(u"|\'%s\'" % querystr)
                        except IndexError:
                            fileout.write(u"|")
                            fileout.write(u"|")

                        #consumer
                        try:
                            fileout.write(u"|\'%s\'" % str(consumer.properties["Name"].value))
                        except:
                            fileout.write(u"|\'%s\'" % str(consumer))
                            
                        try:
                            if "CommandLineTemplate" in consumer.properties:
                                #payload
                                fileout.write(u"|\'%s\'" % str(consumer.properties["CommandLineTemplate"].value))
                            else:
                                fileout.write(u"|")
                        except IndexError:
                            fileout.write(u"|")
                        
                        #CreateSID
                        fileout.write(u"|\'%s\'" % str(filter.properties["CreatorSID"].value))
                        
                        #Source Path
                        fileout.write(u"|\'%s\'" % args.path)
                        
                        fileout.write(u"\n")
                        badwbem = badwbem + 1
        except:
          if badwbem < 1:
             print("Cannot continue. WBEM Repository is incomplete for: %s - %s\n" % (namespace,args.path))
             print(sys.exc_info())
             badwbem = badwbem + 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import sys

    #main(*sys.argv[1:])
    main(sys.argv[1:])
