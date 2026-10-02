# Binary Triage Report: steam.exe

- **Classification Verdict**: `SAFE`
- **Malicious Confidence Score**: `0.00%`
- **SHA-256**: `96e7ece17949f598ccf6aa55dc0194cb4896607b3f369580cf1f998b280e7f4d`
- **File Size**: `5773976 bytes`

---

### PE Structure & Behavioral Signals
- **Total Sections**: `7` (`.text, .rdata, .data, .pdata, .fptable, .rsrc, .reloc`)
- **Max Section Entropy**: `6.66 / 8.00`
- **Total Imports**: `340`
- **High-Risk APIs Detected**: `IsDebuggerPresent, OpenProcess, VirtualAlloc, RegSetValueExA, VirtualProtect`

---

### Remediation Status
- No remediation signature required (File deemed safe).
