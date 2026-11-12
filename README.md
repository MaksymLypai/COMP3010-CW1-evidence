# COMP3010 CW1 - Evidence Portfolio

Evidence for my investigation of the `COMP3010CW1.pcap` capture (27 June 2017): a Windows 7 workstation, FlashGordon-PC (192.168.1.96), infected by a Nemucod JavaScript downloader that installed Shiotob/URLZone, Pushdo/Cutwail and Ursnif/Gozi.

The write-up itself is in my report, this repo is just the evidence behind it so the findings can be checked.

Note: there is no malware and no pcap in here. I hashed the payloads in the isolated VM and deleted them afterwards, so it's only hashes, text output and screenshots.

## Contents

| Folder | What's in it |
|---|---|
| `screenshots/annotated/` | All evidence screenshots (E00-E23) with numbered boxes and captions |
| `screenshots/original/` | The same screenshots without annotations |
| `outputs/` | Text output of every command run in the VM (hashes, alert counts, IOC lists, protocol hierarchy, capinfos, bash history) |
| `outputs/suricata_modern/` | Suricata 8.0.3 + ET Open ruleset (updated 11/11/2026 20:26) re-run on the pcap (`fast.log`, `eve.json`, logs) |
| `outputs/suricata_custom/` | Suricata run with my own two rules |
| `rules/local.rules` | My two custom Suricata rules |
| `notes/analyst-notes.md` | Working notes from the analysis, including mistakes and how I corrected them |
| `notes/timeline.md` | Timeline of the incident with frame numbers and evidence references |
| `notes/iocs.csv` | Indicators of compromise in a machine-readable format |
| `ai-use/` | Log of how I used AI tools during the coursework |

## Environment and method

- VM: Ubuntu 26.04.1 LTS in VMware Workstation, network adapter disconnected, shared folders and clipboard off during the analysis (E01).
- Tools: Wireshark/TShark 4.6.4, Suricata 8.0.3, ET Open ruleset (69,357 rules, updated 11/11/2026), `sha256sum`, `file`.
- pcap SHA256, checked before starting: `aa8bd9280b943db2e729b921de58d5fd37c4f8c76d1aa9996e9e5b44bcf7a7a3` (E01).
- How I worked: started from the IDS alerts, checked them at packet level, exported and hashed the payloads, tested detection, then looked things up online (OSINT). I tried to have two separate sources for each finding.

### Reproducing the key results

```bash
sha256sum COMP3010CW1.pcap
tshark -r COMP3010CW1.pcap -Y dhcp -T fields -e eth.src -e ip.src -e dhcp.option.hostname
tshark -r COMP3010CW1.pcap -Y 'http.request.uri contains ".exe" || http.request.uri contains ".gun"' \
  -T fields -e frame.number -e frame.time_utc -e http.host -e http.request.uri -e http.user_agent
grep '^\[\*\*\]' CW1Snort.txt | sort | uniq -c | sort -rn
grep -E '^(ET|ETPRO|GPL)' CW1Suricata.txt | sort | uniq -c | sort -rn
sudo suricata -r COMP3010CW1.pcap -k none -S rules/local.rules -l out/
```
Payloads: Wireshark -> File -> Export Objects -> HTTP -> save to an isolated folder -> `sha256sum *` and `file *` (don't run them!).
Note: on Ubuntu 26.04 `tshark -r file` was blocked by AppArmor; `cat file | tshark -r - ...` works. Because I piped the file in, `outputs/capinfos.txt` shows `File size: 0 bytes` and `SHA256: <unknown>`. The pcap hash is in E01.

Times: my notes and timeline are in UTC. Suricata 8.0.3 and capinfos in the VM print local time (BST, UTC+1), so 14:38 in `E17_custom_rules.txt`, `E21c_new_leads.txt`, `suricata_modern/`, `suricata_custom/` and `capinfos.txt` means 13:38 UTC. The 2017 `CW1Suricata.txt` is 10h36m off (E07b).

Packet counts: Wireshark shows 1,230 HTTP, 152 SMTP and 1 malformed packet, and those are the numbers in my notes. `protocol_hierarchy.txt` comes from TShark, which does a single pass by default and gets 1,233 HTTP and 150 SMTP (`tshark -2` gives the Wireshark numbers).

## Evidence index

| ID | Shows | Supports |
|---|---|---|
| E00 | TShark version and user groups | Environment |
| E01 | pcap SHA256 and VM isolation | Integrity, safe handling |
| E02 | IPv4 conversations: one internal host, 381 conversations | Q2, scope |
| E03 | DHCP: IP, MAC, hostname, Windows vendor class | Q1-Q3 |
| E04 | Frame 6, GET /gerv.gun, WinHttp User-Agent | Q4-Q5, infection vector |
| E04b | Download requests and responses | Payload timeline |
| E05 | HTTP stream: EXE disguised as .gun, server Date header | Infection, timing |
| E05b | Embedded resource strings in gerv.gun | Masquerading (observation) |
| E06 | Snort alert counts (498 Pushdo) | Q6 |
| E07 | Suricata 2017 alert counts (823 Pushdo) | Q6, IDS comparison |
| E07b | Same packet, different Snort/Suricata timestamps | Timestamp reliability |
| E08a-c | Export Objects: gerv.gun, .exe files, t64.bin | Payload extraction |
| E08d | Correcting the accidental "Save All" | Evidence handling |
| E09 | SHA256 and file types of the payloads | Q8-Q10 |
| E10a-d | VirusTotal: gerv.gun, trow.exe, wp.exe, t64.bin | Malware families |
| E11a-d | VirusTotal and Hybrid Analysis: JS droppers | Q7, infection vector |
| E12a-b | Campaign blog: email lure and hashes | Q7, delivery |
| E13 | Pushdo C2 burst, fake IE6 User-Agent | C2 behaviour |
| E14 | Outbound SMTP connection attempts | Spam behaviour |
| E14b | SMTP server banners | Spam targets, timing |
| E14c | Binary data on port 25 | Limits of the spam evidence |
| E15 | Conficker false positive, Kazy alert (really the wp.exe download), sinkhole hits | IDS accuracy |
| E16a | Suricata version, ruleset, Pushdo rule count | Detection testing |
| E16 | Current Pushdo rule text | Detection logic |
| E17 | My custom rules and their alerts | Detection testing |
| E18 | Protocol hierarchy | Traffic make-up |
| E19 | I/O graph | Timeline overview |
| E20 | DNS queries in order | Timeline, shared infrastructure |
| E21a-d | Current ruleset re-run, new leads, TLS to 208.83.223.34 | IDS comparison, Tor/Gozi |
| E22 | Quarantine deleted | Safe handling |
| E23 | IOC list sizes and User-Agent breakdown | IOCs, real OS |

## VirusTotal links (accessed 11/11/2026)

| File | Report |
|---|---|
| gerv.gun | https://www.virustotal.com/gui/file/0931537889c35226d00ed26962ecacb140521394279eb2ade7e9d2afcf1a7272 |
| trow.exe | https://www.virustotal.com/gui/file/94a0a09ee6a21526ac34d41eabf4ba603e9a30c26e6a1dc072ff45749dfb1fe1 |
| wp.exe | https://www.virustotal.com/gui/file/79d503165d32176842fe386d96c04fb70f6ce1c8a485837957849297e625ea48 |
| t64.bin | https://www.virustotal.com/gui/file/9875dac23b48fe6a52681b113be524a18c503df9b16081be73390ea18614ca68 |
| JS dropper (.pdf.js) | https://www.virustotal.com/gui/file/59727ea201d94d471bdbb353b1281cca3c5bebf5305b140a3c017e52a37be702 |
| JS dropper (doc.js) | https://www.virustotal.com/gui/file/64ae13592c5d8b289be81ebb50e054cef49b0bdf50ea92dd44ed611dd274150f |
