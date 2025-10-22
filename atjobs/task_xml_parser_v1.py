#!/usr/bin/env python

import os
import argparse
import xml.etree.ElementTree as ET

def strip_ns(tag):
    """Remove XML namespace if present"""
    return tag.split('}')[-1] if '}' in tag else tag

def extract_commands(xml_file):
    """Extract Command and Arguments from one XML-like file"""
    results = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for exec_elem in root.iter():
            if strip_ns(exec_elem.tag) == 'Exec':
                command_text = ""
                arguments_text = ""
                for child in exec_elem:
                    tag_name = strip_ns(child.tag)
                    if tag_name == 'Command' and child.text:
                        command_text = child.text.strip()
                    elif tag_name == 'Arguments' and child.text:
                        arguments_text = child.text.strip()
                results.append((command_text, arguments_text))
    except ET.ParseError:
        # Not a valid XML file
        return None
    return results

def main():
    parser = argparse.ArgumentParser(description="Extract Command and Arguments from Windows Task XML files")
    parser.add_argument("-i", "--inputdir", required=True, help="Directory containing task XML files")
    parser.add_argument("-o", "--outfile", required=True, help="Output file path")
    args = parser.parse_args()

    file_exists = os.path.isfile(args.outfile)

    with open(args.outfile, "a", encoding="utf-8") as out_f:
        # Write header once if output file doesn't exist
        if not file_exists:
            out_f.write("command|argument|source file\n")

        for root_dir, dirs, files in os.walk(args.inputdir):
            for file in files:
                file_path = os.path.join(root_dir, file)
                print(f"Processing: {file_path}")
                entries = extract_commands(file_path)

                # Handle unreadable or malformed files
                if entries is None:
                    print(f"Warning: Could not parse {file_path}")
                    out_f.write(f"| |{file_path}\n")
                    continue

                # If no Exec/Command found, still record the file
                if not entries:
                    out_f.write(f"| |{file_path}\n")
                    continue

                # Write each command/argument pair
                for command, arguments in entries:
                    if command or arguments:
                        out_f.write(f"{command}|{arguments}|{file_path}\n")
                    else:
                        out_f.write(f"| |{file_path}\n")

if __name__ == "__main__":
    main()

