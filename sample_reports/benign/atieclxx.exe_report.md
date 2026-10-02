# Binary Triage Report: atieclxx.exe

- **Classification Verdict**: `SAFE`
- **Malicious Confidence Score**: `5.00%`
- **SHA-256**: `845952a3a120a51c361a3ac6e3778274e5ef5495df0af5c3a47f6700e59302bb`
- **File Size**: `971560 bytes`

---

### PE Structure & Behavioral Signals
- **Total Sections**: `6` (`.text, .rdata, .data, .pdata, .rsrc, .reloc`)
- **Max Section Entropy**: `6.40 / 8.00`
- **Total Imports**: `373`
- **High-Risk APIs Detected**: `IsDebuggerPresent, ShellExecuteA, OpenProcess, RegSetValueExA`

---

### Remediation Status
- No remediation signature required (File deemed safe).
