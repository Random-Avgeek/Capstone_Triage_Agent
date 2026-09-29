import os
import shutil
from pathlib import Path

# Target destination folder
TARGET_DIR = Path(r"data\benign")
TARGET_DIR.mkdir(parents=True, exist_ok=True)

# Candidate source directories for diverse compiler toolchains & headers
SOURCE_CONFIGS = [
    {"path": Path(r"C:\Windows\System32"), "limit": 30, "recursive": False},
    {"path": Path(r"C:\Windows\SysWOW64"), "limit": 30, "recursive": False},
    {"path": Path(r"C:\Program Files"), "limit": 30, "recursive": True},
    {"path": Path(r"C:\Program Files (x86)"), "limit": 30, "recursive": True},
]

# File size bounds: 50 KB to 15 MB
MIN_SIZE_BYTES = 50 * 1024
MAX_SIZE_BYTES = 15 * 1024 * 1024

total_collected = 0

for source in SOURCE_CONFIGS:
    src_path = source["path"]
    limit = source["limit"]
    recursive = source["recursive"]

    if not src_path.exists():
        print(f"[!] Directory not found, skipping: {src_path}")
        continue

    print(f"[*] Scanning {src_path} (Target: {limit})...")
    collected_from_dir = 0

    # Choose between flat or recursive traversal
    file_iterator = src_path.rglob("*.exe") if recursive else src_path.glob("*.exe")

    for file_path in file_iterator:
        try:
            # Skip symlinks and shortcuts
            if file_path.is_symlink():
                continue

            file_size = file_path.stat().st_size
            if not (MIN_SIZE_BYTES <= file_size <= MAX_SIZE_BYTES):
                continue

            # Ensure unique filename to prevent overwrite collisions
            dest_file = TARGET_DIR / file_path.name
            if dest_file.exists():
                dest_file = TARGET_DIR / f"{file_path.stem}_{collected_from_dir}{file_path.suffix}"

            shutil.copy2(file_path, dest_file)
            collected_from_dir += 1

            if collected_from_dir >= limit:
                break

        except (PermissionError, FileNotFoundError, OSError):
            continue

    print(f"    -> Extracted {collected_from_dir} executables.")
    total_collected += collected_from_dir

print(f"\n[+] Extraction Complete: {total_collected} benign samples stored in {TARGET_DIR.resolve()}")