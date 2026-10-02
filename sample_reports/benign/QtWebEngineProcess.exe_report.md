# Binary Triage Report: QtWebEngineProcess.exe

- **Classification Verdict**: `SAFE`
- **Malicious Confidence Score**: `3.00%`
- **SHA-256**: `60a27d325002295b8bef4778b6fbf9888f553cb69b55ffcddcd6f7cfb55af17f`
- **File Size**: `684056 bytes`

---

### PE Structure & Behavioral Signals
- **Total Sections**: `6` (`.text, .rdata, .data, .pdata, .rsrc, .reloc`)
- **Max Section Entropy**: `6.55 / 8.00`
- **Total Imports**: `307`
- **High-Risk APIs Detected**: `CreateRemoteThread, IsDebuggerPresent, OpenProcess, VirtualAlloc, WriteProcessMemory`

---

### Remediation Status
- No remediation signature required (File deemed safe).
