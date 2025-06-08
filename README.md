# 🛡️ Post-Compromise Memory Forensics – DFIR Lab (Volatility 3)

> **Analyst:** Sumit Kumar
> **Date:** June 8, 2025
> **Tools:** Volatility 3, Belkasoft RAM Capturer, PowerShell, Sysmon, Windows 10 VM

---

## 📌 Scenario Overview

This lab simulates a real-world post-compromise scenario where a Windows 10 machine has been infected with a PowerShell-based malware that establishes persistence, executes hidden code, and contacts an external server. Using memory capture and Volatility 3, the incident is reconstructed and analyzed from volatile memory.

---

## 🎯 Objectives

* Capture volatile memory after simulated compromise
* Detect signs of persistence (scheduled tasks)
* Identify command & control activity
* Examine injected or malicious memory regions
* Correlate findings with MITRE ATT\&CK techniques

---

## 🧰 Tools Used

* `Belkasoft RAM Capturer` – Memory acquisition
* `Volatility 3` – Memory forensics framework
* `Sysmon + PowerShell logging` – Log generation & visibility
* `Windows Task Scheduler + PowerShell` – Attacker simulation

---

## 🧪 Simulated Attacker Behavior

```powershell
# Simulated malicious script
Start-Sleep -s 9999

# Scheduled Task:
schtasks /create /tn "BackupSyncRunner" /tr "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\Public\backdoor.ps1" /sc onlogon

# Command and Control Beacon:
Invoke-WebRequest -Uri http://example.com -UseBasicParsing
```

---

## 🔬 Volatility Plugins Used

| Plugin                    | Purpose                                    |
| ------------------------- | ------------------------------------------ |
| `windows.pslist`          | List active processes                      |
| `windows.cmdline`         | Extract process arguments                  |
| `windows.malfind`         | Detect RWX memory regions / injections     |
| `windows.scheduled_tasks` | Reveal scheduled persistence mechanisms    |
| `windows.netscan`         | Detect network communications (C2 traffic) |

---

## 📊 Key Findings

```text
Process   : powershell.exe (PID 396)
File      : backdoor.ps1
Task Name : BackupSyncRunner
Memory    : RWX pages injected in PowerShell
Network   : 23.192.228.80:80 (HTTP connection via PowerShell)
```

---

## 🧩 MITRE ATT\&CK Mapping

| Technique ID | Name                                | Detection Source     |
| ------------ | ----------------------------------- | -------------------- |
| T1053.005    | Scheduled Task / Job: Logon Trigger | `scheduled_tasks`    |
| T1059        | PowerShell                          | `pslist`, `cmdline`  |
| T1055.002    | Process Injection                   | `malfind`            |
| T1071.001    | Application Layer Protocol: HTTP(S) | `netscan`, `cmdline` |

---

## 📁 Project Structure

```bash
/post-compromise-memory-analysis/
├── memory/
│   ├── 20250608.mem
│   ├── hash.txt
├── volatility_logs/
│   ├── pslist.txt
│   ├── cmdline.txt
│   ├── malfind.txt
│   ├── netscan.txt
│   └── schedtasks.txt
├── screenshots/
│   ├── ram_capture_done.png
│   ├── Process-tree.png
│   ├── execution.png
├── DFIR_Report_SumitKumar.pdf
├── README.md
```

---

## ✅ Outcome

This simulation validates that memory forensics can uncover:

* Persistence via task scheduler
* PowerShell-based execution
* In-memory code injection
* Network-based C2 activity

All evidence was extracted from RAM and correlated with system activity.

---

## 👨‍💻 Author

```yaml
Name: Sumit Kumar
Role: Security Analyst (DFIR)
Tools: Volatility 3, PowerShell, Sysmon
LinkedIn: [your-link]
GitHub: [your-profile]
```
