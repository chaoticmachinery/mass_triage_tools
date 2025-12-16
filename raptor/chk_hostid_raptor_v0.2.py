#!/usr/bin/env python

#Raptor hostid changer for offline scans
#Written by: Keven Murphy
#Version: 0.2


import os
import json
import zipfile
import shutil
import argparse
from collections import defaultdict
from datetime import datetime

def extract_hostname(zip_filename):
    """Extract hostname from filename like Collection-lab00-2025-12-16T09_11_34Z.zip"""
    base = os.path.basename(zip_filename)
    if not base.startswith("Collection-"):
        return None
    # Remove 'Collection-' prefix and everything from the last '-' before timestamp
    part = base[len("Collection-"):]
    # Find the part before the date (2025-...)
    # The timestamp always starts with 2025- or similar year
    import re
    match = re.search(r'-(\d{4}-\d{2}-\d{2}T)', part)
    if match:
        hostname = part[:match.start()]
        return hostname.rstrip('-')  # in case of trailing dash
    return None  # fallback, should not happen with your naming


def extract_and_read_hostid(zip_path, results, hostid_to_entries):
    """Extract ZIP, read HostID, and record hostname."""
    base_name = os.path.basename(os.path.splitext(zip_path)[0])
    extract_dir = os.path.join(os.path.dirname(zip_path), f"{base_name}_extracted")
    os.makedirs(extract_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

    json_path = os.path.join(extract_dir, "client_info.json")
    if os.path.isfile(json_path):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                hostid = data.get("HostID", "HostID key not found")
        except json.JSONDecodeError:
            hostid = "Error: Invalid JSON"
    else:
        hostid = "Error: client_info.json not found"

    hostname = extract_hostname(zip_path)
    if hostname is None:
        hostname = "unknown_" + base_name

    results.append((zip_path, extract_dir, json_path, hostid, hostname))
    hostid_to_entries[hostid].append((hostname, json_path, zip_path))


def assign_new_hostids(hostid_to_entries):
    """
    Detect cross-hostname HostID conflicts.
    For each original HostID used by multiple hostnames, assign a new unique HostID
    to each hostname group.
    Returns: dict json_path → new_hostid (or None if unchanged)
    """
    updates = {}  # json_path → new_hostid
    used_new_ids = set()

    for original_hostid, entries in hostid_to_entries.items():
        if original_hostid.startswith("Error"):
            continue

        # Group by hostname
        hostname_groups = defaultdict(list)  # hostname → list of (json_path, zip_path)
        for hostname, json_path, zip_path in entries:
            hostname_groups[hostname].append((json_path, zip_path))

        # If only one hostname uses this HostID → no conflict, keep original
        if len(hostname_groups) <= 1:
            continue

        # Conflict: multiple hostnames share the same original HostID
        print(f"Conflict detected: HostID '{original_hostid}' used by {len(hostname_groups)} hostnames: {list(hostname_groups.keys())}")

        # Assign one new unique HostID per hostname
        for hostname, group_items in hostname_groups.items():
            counter = 0
            while True:
                now = datetime.now()
                ts = now.strftime("%Y%m%d%H%M%S") + f"{now.microsecond // 100:04d}{counter:02d}"
                parts = original_hostid.split('-')
                if len(parts) >= 3:
                    new_hostid = "-".join(parts[:3]) + "-" + ts
                else:
                    new_hostid = original_hostid + "-" + ts

                if new_hostid not in used_new_ids:
                    used_new_ids.add(new_hostid)
                    break
                counter += 1

            # Apply the same new HostID to all ZIPs of this hostname with this original ID
            for json_path, zip_path in group_items:
                updates[json_path] = new_hostid
                print(f"  → {hostname} (from {os.path.basename(zip_path)}) gets new HostID: {new_hostid}")

    return updates


def update_json_files(updates):
    """Apply the new HostIDs to the JSON files."""
    for json_path, new_hostid in updates.items():
        try:
            with open(json_path, 'r+', encoding='utf-8') as f:
                data = json.load(f)
                old_hostid = data.get("HostID", "(unknown)")
                data["HostID"] = new_hostid
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()
            print(f"Updated {os.path.basename(os.path.dirname(json_path))} JSON: {old_hostid} → {new_hostid}")
        except Exception as e:
            print(f"Failed to update {json_path}: {e}")


def create_altered_zip_files(results, updates):
    zip_mapping = {}
    for zip_path, extract_dir, json_path, _, hostname in results:
        if json_path in updates:
            new_zip_path = os.path.splitext(zip_path)[0] + "_altered.zip"
            with zipfile.ZipFile(new_zip_path, 'w', zipfile.ZIP_DEFLATED) as new_zip:
                for root, _, files in os.walk(extract_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, extract_dir)
                        new_zip.write(file_path, arcname)
            zip_mapping[zip_path] = new_zip_path
            print(f"Created altered: {os.path.basename(new_zip_path)}")
        else:
            zip_mapping[zip_path] = zip_path
    return zip_mapping


def cleanup_extracted_dirs(results):
    for _, extract_dir, _, _, _ in results:
        if os.path.isdir(extract_dir):
            shutil.rmtree(extract_dir)
            print(f"Cleaned up: {os.path.basename(extract_dir)}")


def copy_to_output(zip_mapping, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    for orig_zip, final_zip in zip_mapping.items():
        dest = os.path.join(output_dir, os.path.basename(final_zip))
        shutil.copy2(final_zip, dest)
        print(f"Copied: {os.path.basename(final_zip)} → output")


def process_all_collections(input_dir, output_dir):
    results = []
    hostid_to_entries = defaultdict(list)

    zip_files = [
        os.path.join(input_dir, f) for f in os.listdir(input_dir)
        if f.startswith("Collection-") and f.endswith(".zip")
    ]

    if not zip_files:
        print("No Collection-*.zip files found.")
        return

    print(f"Found {len(zip_files)} ZIP files. Extracting and analyzing HostIDs...\n")

    for zip_path in zip_files:
        extract_and_read_hostid(zip_path, results, hostid_to_entries)

    # Determine which JSONs need updating (same new ID per hostname on conflict)
    updates = assign_new_hostids(hostid_to_entries)

    # Apply updates to JSON files
    if updates:
        update_json_files(updates)
    else:
        print("No HostID conflicts detected across different hostnames. All kept original.")

    # Re-zip modified ones
    zip_mapping = create_altered_zip_files(results, updates)

    # Cleanup
    cleanup_extracted_dirs(results)

    # Copy to output
    copy_to_output(zip_mapping, output_dir)

    # Summary
    print("\n" + "="*70)
    print("FINAL SUMMARY")
    print("="*70)
    hostname_final_id = {}
    for zip_path, _, json_path, original_hostid, hostname in results:
        final_id = updates.get(json_path, original_hostid)
        if final_id.startswith("Error"):
            final_id = f"[{final_id}]"
        hostname_final_id.setdefault(hostname, final_id)

        status = "[UPDATED]" if json_path in updates else "[unchanged]"
        print(f"{os.path.basename(zip_path)} → Hostname: {hostname.ljust(20)} | Final HostID: {final_id} {status}")

    print("\nPer-hostname final HostID:")
    for hn, fid in sorted(hostname_final_id.items()):
        print(f"  {hn.ljust(25)} → {fid}")


def main():
    parser = argparse.ArgumentParser(
        description="Process Collection ZIPs: ensure same hostname gets same HostID, unique across hosts."
    )
    parser.add_argument("-i", "--input-dir", required=True, help="Input directory with Collection-*.zip files")
    parser.add_argument("-o", "--output-dir", required=True, help="Output directory for processed ZIPs")
    args = parser.parse_args()

    process_all_collections(args.input_dir, args.output_dir)


if __name__ == "__main__":
    main()
