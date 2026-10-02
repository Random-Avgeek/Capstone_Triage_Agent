# Binary Triage Report: wmlaunch.exe

- **Classification Verdict**: `SAFE`
- **Malicious Confidence Score**: `0.00%`
- **SHA-256**: `c78551242a53be6a3a670b096973a478d2db8a0619c0b1b95b42430a8f9b8e48`
- **File Size**: `91136 bytes`

---

### PE Structure & Behavioral Signals
- **Total Sections**: `5` (`.text, .data, .idata, .rsrc, .reloc`)
- **Max Section Entropy**: `6.53 / 8.00`
- **Total Imports**: `167`
- **High-Risk APIs Detected**: `IsDebuggerPresent, VirtualAlloc, VirtualProtect`

---

### Remediation Status
- No remediation signature required (File deemed safe).
