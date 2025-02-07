#!/usr/bin/env python

#Creates a list of sha256 hashes for a given directory
#Then outputs the unique hashes to a file


import os
import hashlib
import argparse

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read the file in chunks to avoid memory overload
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def generate_hashes(directory, output_file):
    hashes = []
    with open(output_file, 'w') as out_file:
        for root, _, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                file_hash = calculate_sha256(full_path)
                if file_hash:
                    hashes.append((file_hash, full_path))
                    out_file.write(f"{file_hash} {full_path}\n")
    return hashes

def filter_unique_hashes(hashes, output_file):
    unique_hashes = {}
    for hash_value, file_path in hashes:
        if hash_value not in unique_hashes:
            unique_hashes[hash_value] = file_path

    with open(output_file, 'w') as out_file:
        for hash_value, file_path in unique_hashes.items():
            out_file.write(f"{hash_value}|{file_path}\n")

def main():
    parser = argparse.ArgumentParser(description="Generate SHA256 hashes for all files in a directory and filter unique ones.")
    parser.add_argument('--directory', type=str, required=True, help="Path to the directory to hash files in.")
    parser.add_argument('--output_file', type=str, required=True, help="File to save the generated hashes and file paths.")
    parser.add_argument('--unique_output_file', type=str, required=True, help="File to save the unique hashes and file paths.")
    
    args = parser.parse_args()
    directory = args.directory
    output_file = args.output_file
    unique_output_file = args.unique_output_file
    
    if not os.path.isdir(directory):
        print(f"The provided path '{directory}' is not a valid directory.")
        return

    # Step 1: Generate hashes for all files in the directory
    hashes = generate_hashes(directory, output_file)
    print(f"Hashes have been written to {output_file}")
    
    # Step 2: Filter unique hashes and write them to the second output file
    filter_unique_hashes(hashes, unique_output_file)
    print(f"Unique hashes have been written to {unique_output_file}")

if __name__ == "__main__":
    main()

