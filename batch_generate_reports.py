import sys
import re
import hashlib
import joblib
import pefile
import pandas as pd
from pathlib import Path

# Directories
SAFE_REPORTS_DIR = Path("reports/safe")
MALICIOUS_REPORTS_DIR = Path("reports/malicious")
SAFE_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
MALICIOUS_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", 
    "CreateRemoteThread", "OpenProcess", "IsDebuggerPresent", 
    "InternetOpenA", "HttpOpenRequestA", "URLDownloadToFileA", 
    "RegSetValueExA", "CreateServiceA", "ShellExecuteA"
}

def compute_sha256(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def extract_strings(file_path: Path, min_length: int = 6, limit: int = 8) -> list:
    with open(file_path, "rb") as f:
        data = f.read()
    pattern = rb"[A-Za-z0-9/\.:_\-]{" + str(min_length).encode() + rb",}"
    found = re.findall(pattern, data)
    cleaned = []
    for s in found:
        decoded = s.decode(errors="ignore")
        if not decoded.startswith("!") and len(decoded) <= 50:
            if decoded not in cleaned:
                cleaned.append(decoded)
        if len(cleaned) >= limit:
            break
    return cleaned

def parse_target_binary(file_path: Path):
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ])
    except Exception:
        return None, None

    features = {
        "filesize": file_path.stat().st_size,
        "num_sections": pe.FILE_HEADER.NumberOfSections,
        "time_date_stamp": pe.FILE_HEADER.TimeDateStamp,
        "characteristics": pe.FILE_HEADER.Characteristics,
        "size_of_optional_header": pe.FILE_HEADER.SizeOfOptionalHeader,
        "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "image_base": pe.OPTIONAL_HEADER.ImageBase,
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "dll_characteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
        "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
        "size_of_headers": pe.OPTIONAL_HEADER.SizeOfHeaders,
    }

    entropies = []
    raw_sizes = []
    section_names = []
    for s in pe.sections:
        entropies.append(s.get_entropy())
        raw_sizes.append(s.SizeOfRawData)
        try:
            name = s.Name.decode().strip("\x00")
            section_names.append(name)
        except Exception:
            pass

    features["max_section_entropy"] = max(entropies) if entropies else 0.0
    features["min_section_entropy"] = min(entropies) if entropies else 0.0
    features["mean_section_entropy"] = sum(entropies) / len(entropies) if entropies else 0.0
    features["total_raw_size"] = sum(raw_sizes) if raw_sizes else 0

    imported_apis = set()
    total_imports = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                total_imports += 1
                if imp.name:
                    imported_apis.add(imp.name.decode(errors="ignore"))

    features["total_imports"] = total_imports
    for api in SUSPICIOUS_APIS:
        features[f"imports_{api}"] = 1 if api in imported_apis else 0

    metadata = {
        "sha256": compute_sha256(file_path),
        "sections": section_names,
        "suspicious_apis_present": [api for api in SUSPICIOUS_APIS if api in imported_apis],
        "strings": extract_strings(file_path),
        "filesize": features["filesize"],
        "max_entropy": features["max_section_entropy"]
    }

    return features, metadata

def write_yara_rule(target_name: str, meta: dict, dest_dir: Path):
    sanitized_name = re.sub(r"[^a-zA-Z0-9_]", "_", target_name)
    rule_name = f"AutoTriage_{sanitized_name}"
    string_lines = [f'        $str_{i} = "{s.replace("\\", "\\\\").replace("\"", "\\\"")}" ascii wide' for i, s in enumerate(meta["strings"])]
    conditions = ["uint16(0) == 0x5A4D", f"filesize < {int(meta['filesize'] * 1.5)}"]
    if string_lines:
        conditions.append("2 of ($str_*)")

    rule_content = f"""/* Auto-Generated Defense Signature */
rule {rule_name}
{{
    meta:
        description = "Remediation signature for {target_name}"
        sha256 = "{meta['sha256']}"
        threat_level = "High"
    strings:
{chr(10).join(string_lines)}
    condition:
        {' and '.join(conditions)}
}}
"""
    yara_file = dest_dir / f"{target_name}.yar"
    with open(yara_file, "w") as f:
        f.write(rule_content)

def write_markdown_report(target_name: str, verdict: str, risk: float, features: dict, meta: dict, dest_dir: Path):
    report_file = dest_dir / f"{target_name}_report.md"
    content = f"""# Binary Triage Report: {target_name}

- **Classification Verdict**: `{verdict}`
- **Malicious Confidence Score**: `{risk:.2f}%`
- **SHA-256**: `{meta['sha256']}`
- **File Size**: `{meta['filesize']} bytes`

---

### PE Structure & Behavioral Signals
- **Total Sections**: `{features['num_sections']}` (`{", ".join(meta['sections'])}`)
- **Max Section Entropy**: `{meta['max_entropy']:.2f} / 8.00`
- **Total Imports**: `{features['total_imports']}`
- **High-Risk APIs Detected**: `{", ".join(meta['suspicious_apis_present']) if meta['suspicious_apis_present'] else "None"}`

---

### Remediation Status
{"- Defensive YARA rule generated: `" + target_name + ".yar`" if verdict == "MALICIOUS" else "- No remediation signature required (File deemed safe)."}
"""
    with open(report_file, "w") as f:
        f.write(content)

def run_batch():
    artifact = joblib.load("triage_model.pkl")
    model = artifact["model"]
    expected_order = artifact["features"]

    files_to_triage = list(Path("data/benign").glob("*.exe")) + list(Path("data/malicious").glob("*.bin"))
    print(f"[*] Found {len(files_to_triage)} total binary samples. Generating individual reports...\n")

    safe_count = 0
    malicious_count = 0

    for idx, file_path in enumerate(files_to_triage, start=1):
        features, meta = parse_target_binary(file_path)
        if not features:
            continue

        input_df = pd.DataFrame([features])[expected_order]
        prediction = model.predict(input_df)[0]
        risk = model.predict_proba(input_df)[0][1] * 100

        if prediction == 1:
            dest = MALICIOUS_REPORTS_DIR
            verdict = "MALICIOUS"
            malicious_count += 1
            write_yara_rule(file_path.name, meta, dest)
        else:
            dest = SAFE_REPORTS_DIR
            verdict = "SAFE"
            safe_count += 1

        write_markdown_report(file_path.name, verdict, risk, features, meta, dest)

        if idx % 25 == 0 or idx == len(files_to_triage):
            print(f"    Processed [{idx}/{len(files_to_triage)}] files...")

    print(f"\n[+] Batch Run Completed!")
    print(f"    - Safe reports created: {safe_count} in {SAFE_REPORTS_DIR.resolve()}")
    print(f"    - Malicious reports & YARA rules created: {malicious_count} in {MALICIOUS_REPORTS_DIR.resolve()}")

if __name__ == "__main__":
    run_batch()