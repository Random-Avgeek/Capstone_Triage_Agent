from pathlib import Path
import pefile

benign_dir = Path("data/benign")
malicious_dir = Path("data/malicious")

benign_samples = list(benign_dir.glob("*.exe"))
malicious_samples = list(malicious_dir.glob("*.bin"))

print(f"[+] Benign samples found: {len(benign_samples)}")
print(f"[+] Malicious samples found: {len(malicious_samples)}")

# Smoke test parsing on one malicious sample
if malicious_samples:
    sample = malicious_samples[0]
    try:
        pe = pefile.PE(sample)
        print(f"\n[+] Smoke test passed on: {sample.name}")
        print(f"    - Subsystem: {hex(pe.OPTIONAL_HEADER.Subsystem)}")
        print(f"    - Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"    - Sections: {[s.Name.decode().strip(chr(0)) for s in pe.sections]}")
    except Exception as e:
        print(f"[!] Smoke test failed: {e}")