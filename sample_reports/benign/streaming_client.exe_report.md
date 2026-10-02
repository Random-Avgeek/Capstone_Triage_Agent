# Binary Triage Report: streaming_client.exe

- **Classification Verdict**: `SAFE`
- **Malicious Confidence Score**: `0.00%`
- **SHA-256**: `3e218ed4c4403c74b1a323f1df962fb7cabc85fc5ff737b63cc4289e8ad430fb`
- **File Size**: `11153048 bytes`

---

### PE Structure & Behavioral Signals
- **Total Sections**: `7` (`.text, .rdata, .data, .pdata, .fptable, .rsrc, .reloc`)
- **Max Section Entropy**: `7.44 / 8.00`
- **Total Imports**: `282`
- **High-Risk APIs Detected**: `IsDebuggerPresent, OpenProcess, VirtualAlloc, VirtualProtect`

---

### Remediation Status
- No remediation signature required (File deemed safe).
