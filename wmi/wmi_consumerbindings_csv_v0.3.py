#!/usr/bin/env python3

#===================================================================================
# Written by: Fireeye Flare Team
# Modified by: Keven Murphy
# Further Modified: Added detection of non-default Event Namespaces without consumers
#                   improved filtering for default namespace prefixes
#                   and CSV inclusion of unused non-default namespaces with -NA- fields
#
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

import sys
import logging
import cim
import re
import os.path
import argparse
import io
import struct
from cim import CIM
from cim.objects import Namespace


def decode_sid(sid_bytes):
    if not sid_bytes or len(sid_bytes) < 8:
        return "<invalid SID>"
    revision = sid_bytes[0]
    sub_auth_count = sid_bytes[1]
    identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder='big')
    sub_authorities = []
    for i in range(sub_auth_count):
        start = 8 + i * 4
        if start + 4 <= len(sid_bytes):
            sub_authorities.append(struct.unpack("<I", bytes(sid_bytes[start:start+4]))[0])
    sid_string = f"S-{revision}-{identifier_authority}-" + "-".join(str(x) for x in sub_authorities)
    return sid_string

def normalize_ns(ns):
    """Normalize namespace strings for consistent comparison."""
    if ns is None:
        return ""
    s = str(ns).lower()
    # remove any leading/trailing backslashes and surrounding whitespace
    s = s.strip().strip('\\')
    return s

def main(argv):
    version = '0.3'
    badwbem = 0

    parser = argparse.ArgumentParser(description="WMI __filtertoconsumerbinding")
    parser.add_argument('-p', '--path', dest='path', help='Source folder "Repository"', required=True)
    parser.add_argument('-t', '--type', dest='wmitype', help='Can be xp or win7', required=True)
    parser.add_argument('-v', '--verbose', dest='verbose', help='Be verbose', action="store_true")
    parser.add_argument('-o', '--out', default='output', help='Output the results to filename', required=True)

    args = parser.parse_args()

    if args.verbose:
        print("WMI Search for ConsumerBinding")
        print("Modified By: Keven Murphy")
        print("Version: %s" % version)
        print("Path: %s" % args.path)
        print("Type: %s\n" % args.wmitype)
        print("Output filename: %s" % args.out)

    if args.wmitype not in ("xp", "win7"):
        raise RuntimeError("Invalid mapping type: {:s}".format(args.wmitype))

    fileout = io.open(args.out, 'a', encoding='utf-8')
    fileout.write(u"'EventNamespace'|'FilterName'|'QueryLanguage'|'Query'|'Consumer'|'CommandLineTemplate'|'ExecutablePath'|'ScriptFilename'|'ScriptText'|'ScriptingEngine'|'CreatorSID'|'Source File Path'\n")

    nameclasses = ['__filtertoconsumerbinding', '__eventconsumer', '__eventfilter']
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

    consumer_namespaces = set()

    for namespace in namespaces:
        namespacestr = str(namespace)
        if args.verbose:
            print("\nSearch namespace: %s" % namespacestr)
        try:
            with Namespace(c, namespacestr[1:]) as ns:
                for nameclass in nameclasses:
                    if args.verbose:
                        print("Checking %s now..." % nameclass)
                    for binding in ns.class_(nameclass).instances:
                        record = []
                        filterref = binding.properties["Filter"].value
                        consumerref = binding.properties["Consumer"].value
                        filter = ns.get(ns.parse_object_path(filterref))
                        consumer = ns.get(ns.parse_object_path(consumerref))

                        # normalize and record that this namespace has a consumer
                        ns_norm = normalize_ns(namespacestr)
                        consumer_namespaces.add(ns_norm)

                        record.append(u"'%s'" % str(ns))
                        record.append(u"'%s'" % str(filter.properties["Name"].value))

                        try:
                            record.append(u"'%s'" % str(filter.properties["QueryLanguage"].value))
                            querystr = re.sub(r'[\n\r]+', " ", str(filter.properties["Query"].value))
                            record.append(u"'%s'" % querystr)
                        except IndexError:
                            record.append(u"")
                            record.append(u"")

                        try:
                            record.append(u"'%s'" % str(consumer.properties["Name"].value))
                        except:
                            record.append(u"'%s'" % str(consumer))

                        for prop_name in ["CommandLineTemplate","ExecutablePath","ScriptFilename","ScriptText","ScriptingEngine"]:
                            try:
                                if prop_name in consumer.properties:
                                    val = consumer.properties[prop_name].value
                                    if isinstance(val, list):
                                        val = ''.join(chr(b) for b in val)
                                    val = str(val).replace("\n", " ").replace("\r", "")
                                    record.append(u"'%s'" % val)
                                else:
                                    record.append(u"")
                            except Exception:
                                record.append(u"")

                        try:
                            raw_sid = filter.properties["CreatorSID"].value
                            sid_bytes = bytes(raw_sid) if isinstance(raw_sid, list) else raw_sid
                            decoded_sid = decode_sid(sid_bytes)
                            record.append(u"'%s'" % decoded_sid)
                        except Exception:
                            record.append(u"<invalid SID>")

                        record.append(u"'%s'" % args.path)
                        fileout.write(u"|".join(record) + u"\n")
                        badwbem += 1
        except Exception:
            if badwbem < 1:
                print("Cannot continue. WBEM Repository is incomplete for: %s - %s\n" % (namespace, args.path))
                print(sys.exc_info())
                badwbem += 1

    # Identify non-default namespaces with no consumers
    default_namespace_prefixes = [
        "root\\cimv2",
        "root\\subscription",
        "root\\default",
        "root\\wmi",
        "root\\security",
        "root\\securitycenter",
        "root\\securitycenter2",
        "root\\servicemodel",
        "root\\directory",
        "root\\microsoft",
        "root\\rsop",
        "root\\policy",
        "root\\interop",
        "root\\virtualization",
        "root\\ccm",
        "root\\hardware",
        "root\\system",
        "root\\cli",
        "root\\standardcimv2",
        "root\\appv",
        "root\\msdtc",
        "root\\inventorylogging",
        "root\\microsoftactivedirectory",
        "root\\microsoftdfs",
        "root\\microsoftdns",
        "root\\nap",
        "root\\sddc",
        "root\\webadministration",
    ]

    def is_default_namespace(ns_str):
        ns_str = ns_str.lower()
        return any(ns_str == prefix or ns_str.startswith(prefix + "\\") for prefix in default_namespace_prefixes)

    no_consumer_namespaces = []
    # For each discovered namespace, if it has no consumer and is NOT a default namespace,
    # then add it to the CSV with -NA- filled columns and also to the printed list.

    for ns in namespaces:
        ns_str = normalize_ns(ns)
        if ns_str not in consumer_namespaces and not is_default_namespace(ns_str):
            # CSV row: EventNamespace populated, other 10 fields = '-NA-', last field = args.path
            record = [f"'{ns_str}'"] + ["'-NA-'" for _ in range(10)] + [f"'{args.path}'"]
            fileout.write(u"|".join(record) + u"\n")
            no_consumer_namespaces.append(ns_str)


    #if no_consumer_namespaces:
    #    print("\n[+] Non-default namespaces without consumers (also written to CSV):")
    #    for ns in sorted(no_consumer_namespaces):
    #        print(f"    {ns}")
    #else:
    #    print("\n[+] No non-default namespaces without consumers found.")

    fileout.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main(sys.argv[1:])
