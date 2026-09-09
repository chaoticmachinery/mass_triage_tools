import os
import json
import zipfile
import time
import shutil
import argparse
from collections import defaultdict
from datetime import datetime


def read_hostid(zip_path):
    """
    Reads the HostID from client_info.json inside the ZIP without extracting it.
    Returns an 'Error: ...' string if the HostID cannot be read.
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            try:
                raw = zip_ref.read("client_info.json")
            except KeyError:
                return "Error: client_info.json not found"
    except zipfile.BadZipFile:
        return "Error: Not a valid ZIP file"

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "Error: Failed to parse JSON"

    hostid = data.get("HostID") if isinstance(data, dict) else None
    if not isinstance(hostid, str) or not hostid:
        return "Error: HostID key missing or not a string"
    return hostid


def make_new_hostid(hostid, used_hostids):
    """
    Builds a new unique HostID from the original first three segments plus a timestamp
    formatted as YYYY-MMDDHHMMSSNN, where NN are the first 2 digits of the microseconds.
    For a UUID-style ID this keeps the 8-4-4-4-12 shape.
    Returns (new_hostid, timestamp).
    """
    while True:
        now = datetime.now()
        timestamp = now.strftime("%Y-%m%d%H%M%S") + now.strftime("%f")[:2]
        parts = hostid.split('-')
        if len(parts) >= 3:
            new_hostid = "-".join(parts[:3]) + "-" + timestamp
        else:
            new_hostid = hostid + "-" + timestamp

        # Ensure uniqueness among HostIDs generated in this run
        if new_hostid not in used_hostids:
            used_hostids.add(new_hostid)
            return new_hostid, timestamp
        time.sleep(0.01)


def write_altered_zip(zip_path, new_zip, new_hostid, hostname_suffix=None):
    """
    Copies zip_path to new_zip entry by entry, preserving entry timestamps, attributes,
    compression and the archive comment. Only client_info.json is rewritten with the new HostID.
    If hostname_suffix is given, Hostname is rewritten as '<Hostname>-<suffix>' as well.
    Returns the Hostname written to the new archive, or None if there was none.
    """
    new_hostname = None
    with zipfile.ZipFile(zip_path, 'r') as src, zipfile.ZipFile(new_zip, 'w') as dst:
        dst.comment = src.comment
        for info in src.infolist():
            if info.filename == "client_info.json":
                data = json.loads(src.read(info))
                data["HostID"] = new_hostid
                if hostname_suffix and isinstance(data.get("Hostname"), str):
                    data["Hostname"] = data["Hostname"] + "-" + hostname_suffix
                new_hostname = data.get("Hostname")
                dst.writestr(info, json.dumps(data, indent=4).encode("utf-8"))
            elif info.is_dir():
                dst.writestr(info, b"")
            else:
                # Stream the entry so large files are not loaded into memory
                with src.open(info) as fsrc, dst.open(info, 'w') as fdst:
                    shutil.copyfileobj(fsrc, fdst)
    return new_hostname


def process_all_collections(input_dir, output_dir, rename_hostname=False):
    """
    Processes all ZIP files starting with 'Collection' from the input directory:
      - Reads the HostID from each one.
      - Assigns a new unique HostID to every member of a duplicate group.
      - With rename_hostname, also suffixes their Hostname with the same timestamp.
      - Writes those as '<name>_altered.zip' in the output directory.
      - Copies all other ZIP files to the output directory unchanged.
    Original ZIP files are never modified.
    """
    input_dir = os.path.abspath(input_dir)
    # A relative output directory is placed beside the input directory
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(os.path.dirname(input_dir), output_dir)
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    results = []  # (zip_path, hostid)
    hostid_map = defaultdict(list)

    for file in sorted(os.listdir(input_dir)):
        if file.startswith("Collection") and file.endswith(".zip") and not file.endswith("_altered.zip"):
            zip_path = os.path.join(input_dir, file)
            hostid = read_hostid(zip_path)
            results.append((zip_path, hostid))
            hostid_map[hostid].append(zip_path)

    # Assign a new HostID to every member of a duplicate group
    new_hostids = {}  # zip_path -> (new_hostid, timestamp)
    used_hostids = set()
    for hostid, zip_paths in hostid_map.items():
        if len(zip_paths) > 1 and not hostid.startswith("Error:"):
            for zip_path in zip_paths:
                new_hostids[zip_path] = make_new_hostid(hostid, used_hostids)

    for zip_path, hostid in results:
        name = os.path.basename(zip_path)
        if zip_path in new_hostids:
            new_zip = os.path.join(output_dir, os.path.splitext(name)[0] + "_altered.zip")
            new_hostid, timestamp = new_hostids[zip_path]
            new_hostname = write_altered_zip(zip_path, new_zip, new_hostid,
                                             timestamp if rename_hostname else None)
            hostname_note = f"  Hostname: {new_hostname or '(none)'}" if rename_hostname else ""
            print(f"{name} -> Old HostID: {hostid}  =>  New HostID: {new_hostid}{hostname_note} [UPDATED] -> {new_zip}")
        else:
            dest = os.path.join(output_dir, name)
            if dest != zip_path:
                shutil.copy2(zip_path, dest)
            print(f"{name} -> HostID: {hostid}")


def main():
    parser = argparse.ArgumentParser(description="Process ZIP files and update duplicate HostIDs.")
    parser.add_argument("-i", "--input-dir", required=True, help="Directory containing the ZIP files.")
    parser.add_argument("-o", "--output-dir", required=True, help="Directory to write the final ZIP files to. A relative path is created beside the input directory.")
    parser.add_argument("-r", "--rename-hostname", action="store_true",
                        help="Also suffix the Hostname of rewritten collections with the same timestamp, "
                             "so Velociraptor's import creates a separate client for each one.")
    args = parser.parse_args()

    process_all_collections(args.input_dir, args.output_dir, args.rename_hostname)


if __name__ == "__main__":
    main()
