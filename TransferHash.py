import os
import hashlib
import argparse
import json
from tqdm import tqdm
import shutil

#Read do not scan file to give user ability to reject direcotires
def read_do_not_scan_file(do_not_scan_file_path):
    do_not_scan_paths = []

    with open(do_not_scan_file_path, 'r') as file:
        lines = file.readlines()

    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            do_not_scan_paths.append(line)

    return do_not_scan_paths

# determine what the script should scan.
def should_scan(file_path, do_not_scan_paths):
    for path in do_not_scan_paths:
        if file_path.startswith(path):
            return False

    head, tail = os.path.split(file_path)
    if tail.startswith('.'):
        return False

    return True


# Function to generate a SHA-256 hash for a given file
def generate_hash(file_path, block_size=65536):
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as file:
            for block in iter(lambda: file.read(block_size), b''):
                hasher.update(block)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    return hasher.hexdigest()


# Generator function to iterate through all files in a directory tree
def get_all_files(base_dir, do_not_scan_paths):
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.')]  # Skip hidden directories
        for file in files:
            file_path = os.path.join(root, file)
            if should_scan(file_path, do_not_scan_paths):
                print(f"Crawling: {file_path}\r", end="")
                yield file_path


def load_do_not_scan_paths(do_not_scan_file):
    do_not_scan_paths = []
    if os.path.exists(do_not_scan_file):
        with open(do_not_scan_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith("#") and line.startswith("File Paths:"):
                    break
            for line in f:
                line = line.strip()
                if not line.startswith("#") and line:
                    do_not_scan_paths.append(line)
    return do_not_scan_paths

# Function to generate hashes for all files in a directory tree and store them in a JSON file
def create_hashes_file(base_dir, hashes_file_path, do_not_scan_paths):
    all_files = list(get_all_files(base_dir, do_not_scan_paths))
    hashes = {}
    file_not_found = 0
    permission_issue = 0
    operating_system_error = 0

    if os.path.exists(hashes_file_path):
        with open(hashes_file_path, 'r') as hashes_file:
            hashes = json.load(hashes_file)

    # Using tqdm for displaying a progress bar
    for file_path in tqdm(all_files, desc="Generating hashes", unit="file"):
        try:
            file_hash = generate_hash(file_path)
            hashes[file_path] = file_hash
        except FileNotFoundError:
            print(f"Warning: File not found or moved: {file_path}")
            file_not_found += 1
        except PermissionError:
            print(f"Warning: Permission denied for file: {file_path}")
            permission_issue +=1
        except OSError:
            print(f"Warning: Permission denied for file: {file_path}")
            operating_system_error +=1

    with open(hashes_file_path, 'w') as hashes_file:
        json.dump(hashes, hashes_file)


    if permission_issue > 0:
        print(f"There were {permission_issue} file permission errors, consider running script as SUDO")
    if operating_system_error > 0:
        print(f"There were {operating_system_error} file permission errors, consider running script as SUDO")

    print(f"Hashes stored in {hashes_file_path}")

def backup_files(src_dir, dest_dir, hashes_file_path, do_not_scan_paths):
    all_files = list(get_all_files(src_dir, do_not_scan_paths))

    hashes = {}
    # Backup and generate hashes
    for file_path in tqdm(all_files, desc="Backing up and generating hashes", unit="file"):
        file_hash = generate_hash(file_path)
        hashes[file_path] = file_hash

        rel_path = os.path.relpath(file_path, src_dir)
        dest_file_path = os.path.join(dest_dir, rel_path)
        dest_file_dir = os.path.dirname(dest_file_path)
        try:
            os.makedirs(dest_file_dir, exist_ok=True)
            shutil.copy2(file_path, dest_file_path)
        except FileNotFoundError:
            print(f"File not being backed up: {file_path}")
        except OSError:
            print(f"OS Error on file {file_path}")

    # Save hashes
    with open(hashes_file_path, 'w') as hashes_file:
        json.dump(hashes, hashes_file, indent=2)
    print(f"Hashes stored in {hashes_file_path}")

    # Verify copied files
    failed_verification = []
    for file_path, file_hash in tqdm(hashes.items(), desc="Verifying files", unit="file"):
        rel_path = os.path.relpath(file_path, src_dir)
        dest_file_path = os.path.join(dest_dir, rel_path)
        dest_file_hash = generate_hash(dest_file_path)

        if dest_file_hash != file_hash:
            failed_verification.append((file_path, dest_file_path))

    if failed_verification:
        print("Failed verifications:")
        for src, dest in failed_verification:
            print(f"Source: {src} - Destination: {dest}")
    else:
        print("All files verified successfully.")


# Function to find duplicate files using the stored hashes
def find_duplicates(hashes_file_path):
    hashes = {}
    duplicates = []

    with open(hashes_file_path, 'r') as hashes_file:
        stored_hashes = json.load(hashes_file)

    # Using tqdm for displaying a progress bar
    for file_path, file_hash in tqdm(stored_hashes.items(), desc="Checking for duplicates", unit="file"):
        if file_hash not in hashes:
            hashes[file_hash] = file_path
        else:
            duplicates.append((file_path, hashes[file_hash]))

    if duplicates:
        script_dir = os.path.dirname(os.path.realpath(__file__))
        duplicates_file_path = os.path.join(script_dir, "duplicates.txt")

        with open(duplicates_file_path, "w") as duplicates_file:
            for dup in duplicates:
                duplicates_file.write(f"{dup[0]}\n{dup[1]}\n\n")

        print(f"Found {len(duplicates)} duplicates.")
        print(f"Duplicates stored in {duplicates_file_path}")
    else:
        print("No duplicates found.")

        print("No duplicates found.")

# Main function that handles command line arguments and calls appropriate functions
def main():
    parser = argparse.ArgumentParser(description="Generate file hashes, check for duplicates, and backup files")
    parser.add_argument("base_dir", help="The directory to process")


    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-g", "--hash", action="store_true", help="Generate and store file hashes")
    group.add_argument("-c", "--check", action="store_true", help="Check for duplicate files")
    group.add_argument("-b", "--backup", nargs=2, metavar=("FROM", "TO"), help="Backup files from one directory to another and verify with hashes")


    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.realpath(__file__))
    hashes_file_path = os.path.join(script_dir, "hashes.json")
    do_not_scan_file_path = os.path.join(script_dir, "doNotScan.txt")
    do_not_scan_paths = load_do_not_scan_paths(do_not_scan_file_path)

    do_not_scan_paths = []
    if os.path.exists(do_not_scan_file_path):
        do_not_scan_paths = read_do_not_scan_file(do_not_scan_file_path)

    if args.hash:
        create_hashes_file(args.base_dir, hashes_file_path, do_not_scan_paths)
    elif args.check:
        find_duplicates(hashes_file_path)
    elif args.backup:
        backup_src, backup_dest = args.backup
        backup_files(backup_src, backup_dest, hashes_file_path, do_not_scan_paths)  # Pass do_not_scan_paths here

if __name__ == "__main__":
    main()
