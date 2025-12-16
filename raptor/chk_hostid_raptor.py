import os
import json
import zipfile
import time
import shutil
import argparse
from collections import defaultdict
from datetime import datetime

def extract_and_read_hostid(zip_path, results, hostid_map):
    """Extracts a ZIP file, reads client_info.json, and stores the HostID."""
    extract_dir = os.path.splitext(zip_path)[0]  # Remove .zip extension
    os.makedirs(extract_dir, exist_ok=True)  # Ensure extraction directory exists

    # Extract ZIP contents
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

    # Path to client_info.json
    json_path = os.path.join(extract_dir, "client_info.json")

    # Read and store the HostID
    if os.path.isfile(json_path):
        try:
            with open(json_path, 'r') as json_file:
                data = json.load(json_file)
                hostid = data.get("HostID", "HostID key not found in JSON")
        except json.JSONDecodeError:
            hostid = "Error: Failed to parse JSON"
    else:
        hostid = "Error: client_info.json not found"

    results.append((zip_path, extract_dir, json_path, hostid))
    hostid_map[hostid].append(json_path)

def update_duplicate_hostids(hostid_map):
    """
    For each duplicate HostID, update the client_info.json files with a new unique HostID.
    The new HostID uses the original first three segments and appends a timestamp
    formatted as YYYY-MMDDHHMMSSNN, where NN are the first 2 digits of the microseconds.
    Returns a mapping of json file paths to (original_hostid, new_hostid) for updated files.
    """
    updated_mapping = {}  # Maps json_path to (original_hostid, new_hostid)
    updated_hostids = set()

    for hostid, json_paths in hostid_map.items():
        if len(json_paths) > 1 and "Error" not in hostid:
            for json_path in json_paths:
                original_hostid = hostid
                # Loop until a unique new HostID is generated
                while True:
                    now = datetime.now()
                    # Create a timestamp: YYYY-MMDDHHMMSS + first 2 digits of microseconds
                    timestamp = now.strftime("%Y-%m%d%H%M%S") + now.strftime("%f")[:2]
                    parts = hostid.split('-')
                    if len(parts) >= 3:
                        new_hostid = "-".join(parts[:3]) + "-" + timestamp
                    else:
                        new_hostid = hostid + "-" + timestamp

                    # Ensure uniqueness among updated HostIDs
                    if new_hostid not in updated_hostids:
                        updated_hostids.add(new_hostid)
                        break
                    else:
                        time.sleep(0.2)

                # Update the JSON file with the new HostID
                try:
                    with open(json_path, 'r+') as json_file:
                        data = json.load(json_file)
                        data["HostID"] = new_hostid
                        json_file.seek(0)
                        json.dump(data, json_file, indent=4)
                        json_file.truncate()
                    updated_mapping[json_path] = (original_hostid, new_hostid)
                    print(f"Updated {json_path} -> Old HostID: {original_hostid} | New HostID: {new_hostid}")
                except (json.JSONDecodeError, IOError) as e:
                    print(f"Error updating {json_path}: {e}")
    return updated_mapping

def create_altered_zip_files(results, updated_mapping):
    """
    For each processed ZIP file whose client_info.json was updated,
    re-zip the extracted directory into a new zip file with '_altered' before the .zip extension.
    Returns a mapping from the original zip file path to the final zip file path.
    For ZIP files not updated, the mapping will simply use the original ZIP file.
    """
    zip_mapping = {}
    for zip_file, extract_dir, json_path, _ in results:
        if json_path in updated_mapping:
            # Only create an altered zip if the JSON was updated
            new_zip = os.path.splitext(zip_file)[0] + "_altered.zip"
            with zipfile.ZipFile(new_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Walk through the extracted directory and add files to the new zip file.
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        filepath = os.path.join(root, file)
                        # Compute the archive name relative to the extracted directory.
                        arcname = os.path.relpath(filepath, extract_dir)
                        zipf.write(filepath, arcname=arcname)
            zip_mapping[zip_file] = new_zip
            print(f"Created altered zip file: {new_zip}")
        else:
            # No update; use the original zip file
            zip_mapping[zip_file] = zip_file
    return zip_mapping

def delete_extracted_dirs(results):
    """Deletes the directories that were created from extracting the ZIP files."""
    for _, extract_dir, _, _ in results:
        if os.path.isdir(extract_dir):
            shutil.rmtree(extract_dir)
            print(f"Deleted extracted directory: {extract_dir}")

def copy_zip_files(zip_mapping, output_dir):
    """
    Copies the final zip files (altered or original) to the specified output directory.
    """
    os.makedirs(output_dir, exist_ok=True)
    for orig_zip, final_zip in zip_mapping.items():
        dest = os.path.join(output_dir, os.path.basename(final_zip))
        shutil.copy2(final_zip, dest)
        print(f"Copied {final_zip} to {dest}")

def process_all_collections(input_dir, output_dir):
    """
    Processes all ZIP files starting with 'Collection' from the input directory:
      - Extracts them.
      - Reads HostIDs.
      - Updates duplicates with unique HostIDs.
      - Creates altered zip files for those that were updated.
      - Deletes extracted directories.
      - Copies the final zip files to the output directory.
    """
    results = []
    hostid_map = defaultdict(list)

    # Change to the input directory
    os.chdir(input_dir)

    # Process each ZIP file in the input directory
    for file in os.listdir():
        if file.startswith("Collection") and file.endswith(".zip"):
            extract_and_read_hostid(file, results, hostid_map)

    # Update duplicate HostIDs and get mapping of updated JSON files
    updated_mapping = update_duplicate_hostids(hostid_map)

    # Create new zip files for those that were updated (and use original for others)
    zip_mapping = create_altered_zip_files(results, updated_mapping)

    # Delete the extracted directories after zipping them up
    delete_extracted_dirs(results)

    # Print summary at the end
    print("\nSummary of processed files:")
    for zip_file, _, json_path, orig_hostid in results:
        if json_path in updated_mapping:
            old_id, new_id = updated_mapping[json_path]
            print(f"{zip_file} -> Old HostID: {old_id}  =>  New HostID: {new_id} [UPDATED]")
        else:
            print(f"{zip_file} -> HostID: {orig_hostid}")

    # Copy the final zip files to the output directory
    copy_zip_files(zip_mapping, output_dir)

def main():
    parser = argparse.ArgumentParser(description="Process ZIP files and update duplicate HostIDs.")
    parser.add_argument("-i", "--input-dir", required=True, help="Directory containing the ZIP files.")
    parser.add_argument("-o", "--output-dir", required=True, help="Directory to copy the final ZIP files to.")
    args = parser.parse_args()

    process_all_collections(args.input_dir, args.output_dir)

if __name__ == "__main__":
    main()
