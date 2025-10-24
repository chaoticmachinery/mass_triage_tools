#!/usr/bin/env python3
#
# CryptnetUrlCache Metadata Parser (Enhanced)
# -------------------------------------------
# Parses CryptnetUrlCache metadata files from Windows systems.
# Outputs pipe-delimited CSV, JSON, or JSONL. Optionally calculates MD5
# of the cached content.
#
# Features:
# - Pipe-delimited CSV output
# - Includes LastModificationTimeHeader
# - URL size and UTF-16 validation to skip invalid files
# - Optional MD5 hash of cached content
#
# Command-line arguments:
# ----------------------
# -i / --dirs        : List of directories to scan for certutil cache files.
#                      Default: common Windows CryptnetUrlCache Metadata paths.
#
# -o / --output      : File path to write output. Default: stdout
#
# --outputFormat     : Output format. Choices: 'csv' (default), 'json', 'jsonl'
#
# --useContent       : If set, attempts to locate the cached content file and
#                      calculate its MD5 hash.
#
# --noHeaders        : If set, CSV output will not include column headers.
#
# --maxWorkers       : Maximum number of threads to use for parsing (default: 1)
#
# --showFiles        : Show the filename that is being parsed
#
# Example usage:
# --------------
# python3 CryptnetUrlCacheParser_MT.py \
#     -i "/media/crypt13/netwitness/training/certutil_test" \
#     -o "test.csv" \
#     --useContent \
#     --maxWorkers 8
#
# This will scan the specified directory, calculate MD5 for found cached files,
# and write pipe-delimited CSV output to 'test.csv'.
#
# Author: AbdulRhman Alfaifi
# Moddied by: Keven Murphy
# License: GPL v1.2
#
# Note All timestamps are in UTC.
#
###################################################################################


import os
import struct
import hashlib
from datetime import datetime, timedelta
import sys
import glob
import argparse
import csv
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "2.0"  # Script version

class CertutilCacheParser:
    def __init__(self, filePath):
        self.filePath = filePath
        if not os.path.isfile(self.filePath):
            raise FileNotFoundError(f"The cache file '{self.filePath}' not found.")

    def FILETIMEToISO(self, ft):
        try:
            us = (ft - 116444736000000000) // 10
            dtObj = datetime(1970, 1, 1) + timedelta(microseconds=us)
            return dtObj.isoformat()
        except Exception:
            return "1601-01-01T00:00:00"

    def MD5(self, fname):
        try:
            hash_md5 = hashlib.md5()
            with open(fname, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest().upper()
        except Exception:
            return "00000000000000000000000000000000"

    def Parse(self, useContent=True):
        parsedData = {}
        with open(self.filePath, "rb") as cacheFile:
            fsize = os.path.getsize(self.filePath)
            if fsize < 120:
                return None

            # Read UrlSize (uint32 @ offset 12)
            cacheFile.seek(12)
            try:
                urlSize = struct.unpack("<I", cacheFile.read(4))[0]
            except struct.error:
                return None
            if urlSize == 0 or urlSize > 4096:
                return None

            # DownloadTime
            try:
                downloadTime = struct.unpack("<Q", cacheFile.read(8))[0]
            except struct.error:
                return None

            # LastModificationTimeHeader @ offset 88
            cacheFile.seek(88)
            modtime_raw = cacheFile.read(8)
            last_mod_time = self.FILETIMEToISO(struct.unpack("<Q", modtime_raw)[0]) if len(modtime_raw) == 8 else "1601-01-01T00:00:00"

            # etagSize @ offset 100
            cacheFile.seek(100)
            try:
                etagSize = struct.unpack("<I", cacheFile.read(4))[0]
            except struct.error:
                etagSize = 0

            # fileSize @ offset 112
            cacheFile.seek(112)
            try:
                fileSize = struct.unpack("<I", cacheFile.read(4))[0]
            except struct.error:
                fileSize = 0

            # UTF-16 URL validation
            cacheFile.seek(116)
            url_preview = cacheFile.read(min(512, fsize - 116))
            try:
                url_text = url_preview.decode("utf-16", errors="ignore")
            except Exception:
                return None
            if not any(c.isprintable() for c in url_text):
                return None

            # Full URL
            cacheFile.seek(116)
            try:
                url = b"".join(struct.unpack(f"{urlSize}c", cacheFile.read(urlSize))).decode("utf-16-le")[0:-1]
            except Exception:
                url = ""

            # ETag
            try:
                hash = (
                    b"".join(struct.unpack(f"{etagSize}c", cacheFile.read(etagSize)))
                    .decode("utf-16-le", errors="ignore")
                    .replace('"', "")
                    [0:-1]
                    if etagSize > 0
                    else ""
                )
            except Exception:
                hash = "Not Found"

            parsedData.update(
                {
                    "LastDownloadTime": self.FILETIMEToISO(downloadTime),
                    "LastModificationTimeHeader": last_mod_time,
                    "URL": url,
                    "FileSize": fileSize,
                    "ETag": hash,
                    "FullPath": cacheFile.name,
                }
            )

            if useContent:
                contentFilePath = os.path.join(
                    os.path.dirname(cacheFile.name), "..", "Content", os.path.basename(cacheFile.name)
                )
                parsedData["MD5"] = self.MD5(contentFilePath)

        return parsedData


if __name__ == "__main__":

    certutilCachePaths = [
        "C:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\Metadata",
        "C:\\Windows\\SysWOW64\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\Metadata",
    ] + glob.glob("C:\\Users\\*\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData")

    parser = argparse.ArgumentParser(description="CryptnetUrlCache Metadata Parser - Multi-threaded")
    parser.add_argument("-i", "--dirs", nargs="+", default=certutilCachePaths, help="Directories containing certutil cache files")
    parser.add_argument("-o", "--output", default=sys.stdout, help="Output file path (default: stdout)")
    parser.add_argument("--outputFormat", default="csv", choices=["csv", "json", "jsonl"], help="Output format")
    parser.add_argument("--useContent", action="store_true", default=False, help="Calculate MD5 of cached content")
    parser.add_argument("--noHeaders", action="store_true", default=False, help="Suppress CSV headers")
    parser.add_argument("--maxWorkers", type=int, default=1, help="Maximum number of threads to use for parsing (default: 1)")
    parser.add_argument("--showFiles", action="store_true", default=False, help="Print each file being parsed")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}", help="Show program version and exit")
    args = parser.parse_args()

    # Friendly usage summary if no args
    if len(sys.argv) == 1:
        print(f"\nCryptnetUrlCacheParser_MT.py version {__version__}")
        print("Usage: python3 CryptnetUrlCacheParser_MT.py [options]\n")
        print("Options:")
        print("  -i / --dirs          List of directories to scan (default: common Windows cache paths)")
        print("  -o / --output        Output file path (default: stdout)")
        print("  --outputFormat       Output format: csv (default), json, jsonl")
        print("  --useContent         Calculate MD5 of cached content if available")
        print("  --noHeaders          Suppress CSV headers")
        print("  --maxWorkers         Maximum number of threads to use (default: 1)")
        print("  --showFiles          Print each file being parsed")
        print("  --version            Show program version and exit")
        print("\nExample:")
        print(f"  python3 CryptnetUrlCacheParser_MT.py -i /path/to/cache -o output.csv --useContent --maxWorkers 8 --showFiles\n")
        sys.exit(0)

    # Gather all files
    all_files = []
    for path in args.dirs:
        for root, dirs, files in os.walk(path):
            for file in files:
                all_files.append(os.path.join(root, file))

    # Setup CSV writer if needed
    if args.outputFormat == "csv":
        f = open(args.output, "w", newline="", encoding="utf-8") if isinstance(args.output, str) else args.output
        results = csv.writer(f, quoting=csv.QUOTE_NONNUMERIC, lineterminator="\n", delimiter="|")
        headers = ["LastDownloadTime", "LastModificationTimeHeader", "URL", "FileSize", "ETag", "FullPath"]
        if args.useContent:
            headers.append("MD5")
        if not args.noHeaders:
            results.writerow(headers)
    elif args.outputFormat == "json":
        results = []
    else:
        f = open(args.output, "w", encoding="utf-8") if isinstance(args.output, str) else args.output
        results = f

    # Multi-threaded parsing
    results_list = []

    def process_file(file_path):
        if args.showFiles:
            print(f"Parsing: {file_path}")
        try:
            return CertutilCacheParser(file_path).Parse(useContent=args.useContent)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=args.maxWorkers) as executor:
        future_to_file = {executor.submit(process_file, fpath): fpath for fpath in all_files}
        for future in as_completed(future_to_file):
            res = future.result()
            if res:
                results_list.append(res)

    # Write results sequentially
    for res in results_list:
        if args.outputFormat == "csv":
            row = [
                res.get("LastDownloadTime"),
                res.get("LastModificationTimeHeader"),
                res.get("URL"),
                res.get("FileSize"),
                res.get("ETag"),
                res.get("FullPath"),
            ]
            if args.useContent:
                row.append(res.get("MD5"))
            results.writerow(row)
        elif args.outputFormat == "json":
            results.append(res)
        else:
            results.write(json.dumps(res) + "\n")

    # JSON output write
    if args.outputFormat == "json":
        out = open(args.output, "w", encoding="utf-8") if isinstance(args.output, str) else args.output
        out.write(json.dumps(results, indent=2))
