import sys
import re
import hashlib
import joblib
import pefile
import pandas as pd
from pathlib import Path

# High-risk Win32 APIs tracked by the model
SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", 
    "CreateRemoteThread", "OpenProcess", "IsDebuggerPresent", 
    "InternetOpenA", "HttpOpenRequestA", "URLDownloadToFileA", 
    "RegSetValueExA", "CreateServiceA", "ShellExecuteA"
}

def compute_sha256(file_path: Path) -> str:
    """Calculates SHA-256 hash of the target binary."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def extract_strings(file_path: Path, min_length: int = 6, limit: int = 8) -> list:
    """Extracts candidate unique ASCII strings for YARA signature generation."""
    with open(file_path, "rb") as f:
        data = f.read()
    pattern = rb"[A-Za-z0-9/\.:_\-]{" + str(min_length).encode() + rb",}"
    found = re.findall(pattern, data)
    
    # Filter common noise and retain unique strings
    cleaned = []
    for s in found:
        decoded = s.decode(errors="ignore")
        if not decoded.startswith("!") and len(decoded) <= 50:
            if decoded not in cleaned:
                cleaned.append(decoded)
        if len(cleaned) >= limit:
            break
    return cleaned

def parse_target_binary(file_path: Path) -> tuple:
    """Extracts features matching the training format and metadata for YARA."""
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ])
    except Exception as e:
        print(f"[!] PE parsing failed: {e}")
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
        "filesize": features["filesize"]
    }

    return features, metadata

def generate_yara_rule(target_name: str, meta: dict, rule_out_path: Path):
    """Synthesizes an exportable YARA rule using extracted forensic indicators."""
    sanitized_name = re.sub(r"[^a-zA-Z0-9_]", "_", target_name)
    rule_name = f"AutoTriage_{sanitized_name}"

    string_lines = []
    conditions = [f"uint16(0) == 0x5A4D", f"filesize < {int(meta['filesize'] * 1.5)}"]

    for idx, s in enumerate(meta["strings"]):
        escaped_str = s.replace("\\", "\\\\").replace('"', '\\"')
        string_lines.append(f'        $str_{idx} = "{escaped_str}" ascii wide')

    if string_lines:
        conditions.append(f"2 of ($str_*)")

    rule_template = f"""/*
 * Auto-Generated Triage Remediation Rule
 * Target Hash: {meta['sha256']}
 */
rule {rule_name}
{{
    meta:
        description = "Automated defense signature generated for {target_name}"
        sha256 = "{meta['sha256']}"
        author = "Capstone Triage Agent"
        threat_level = "High"

    strings:
{chr(10).join(string_lines)}

    condition:
        {' and '.join(conditions)}
}}
"""
    with open(rule_out_path, "w") as f:
        f.write(rule_template)

    print(f"[+] Defensive YARA rule compiled and written to: {rule_out_path.resolve()}")

def run_triage(target_file_path: str):
    target = Path(target_file_path)
    if not target.exists():
        print(f"[!] Target file not found: {target}")
        return

    print(f"\n[*] INGESTING BINARY: {target.name}")
    print(f"[*] Calculating static features and section entropy...")

    features, meta = parse_target_binary(target)
    if not features:
        return

    # Load trained ML model artifact
    artifact = joblib.load("triage_model.pkl")
    model = artifact["model"]
    expected_order = artifact["features"]

    # Align extracted features with training order
    input_df = pd.DataFrame([features])[expected_order]

    # Model inference
    prediction = model.predict(input_df)[0]
    probabilities = model.predict_proba(input_df)[0]
    malicious_prob = probabilities[1] * 100

    print("\n" + "="*45)
    print("           TRIAGE INCIDENT REPORT")
    print("="*45)
    print(f"File Name         : {target.name}")
    print(f"SHA-256 Hash      : {meta['sha256']}")
    print(f"Sections Detected : {', '.join(meta['sections'])}")
    print(f"Suspicious Imports: {', '.join(meta['suspicious_apis_present']) if meta['suspicious_apis_present'] else 'None detected'}")
    print(f"Malicious Risk    : {malicious_prob:.2f}%")
    
    if prediction == 1:
        print(f"VERDICT           : [!] MALICIOUS (Incident Confirmed)")
        print("\n[*] Initializing Automated Remediation Engine...")
        yara_output = Path(f"{target.stem}_remediation.yar")
        generate_yara_rule(target.name, meta, yara_output)
    else:
        print(f"VERDICT           : [-] BENIGN (No immediate remediation required)")
    print("="*45)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python triage_and_remediate.py <path_to_binary>")
    else:
        run_triage(sys.argv[1])