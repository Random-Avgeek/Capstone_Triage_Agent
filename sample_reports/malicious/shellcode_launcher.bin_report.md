# Binary Triage Report: shellcode_launcher.bin

- **Classification Verdict**: `MALICIOUS`
- **Malicious Confidence Score**: `100.00%`
- **SHA-256**: `5edacaca676c927246d9cf5706bb5917025ca8409c24e2af0953bbd2fcc4b8a4`
- **File Size**: `49152 bytes`

---

### PE Structure & Behavioral Signals
- **Total Sections**: `3` (`.text, .rdata, .data`)
- **Max Section Entropy**: `6.31 / 8.00`
- **Total Imports**: `46`
- **High-Risk APIs Detected**: `VirtualAlloc`

---

### Remediation Status
- Defensive YARA rule generated: `shellcode_launcher.bin.yar`
