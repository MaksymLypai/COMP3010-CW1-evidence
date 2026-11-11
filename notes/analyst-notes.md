# Analyst notes - COMP3010 CW1

Working notes from the VM session on 11/11/2026. "Confirmed" means I have checked it myself in the VM and have a screenshot. "To check" is what I expect to see, based on the first pass of the analysis.

## Analysis environment
| Item | Value | Status | Evidence |
|---|---|---|---|
| Host | Windows 11, VMware Workstation | Confirmed | |
| Guest | Ubuntu 26.04.1 LTS, hostname cw-analysis-vm | Confirmed | E00 |
| Wireshark / TShark | 4.6.4 | Confirmed | E00 |
| Suricata | 8.0.3 | Confirmed | E16a |
| ET Open ruleset (updated 11/11/2026 20:26) | 69,357 rules, 53,385 enabled | Confirmed | E16a |
| Pushdo rules in current ruleset | 6 in total, 4 enabled by default | Confirmed | E16a |
| Snapshots | "clean + tools", "tools + rules" | Confirmed | |
| Isolation | ens33 DOWN, only loopback up; /mnt/hgfs not connected; drag and drop and clipboard disabled. Checked 20:45. | Confirmed | E01 |

## Evidence files
Copied into the VM at 20:19 through a temporary shared folder, which was disabled afterwards.

| File | Size (bytes) | SHA256 | Status |
|---|---|---|---|
| COMP3010CW1.pcap | 12,389,606 | aa8bd9280b943db2e729b921de58d5fd37c4f8c76d1aa9996e9e5b44bcf7a7a3 | Confirmed, same hash as on the host, so the copy is intact (E01) |
| CW1Snort.txt | 233,205 | | Confirmed |
| CW1Suricata.txt | 302,394 | | Confirmed |

## Capture overview
| Item | Value | Status | Evidence |
|---|---|---|---|
| Time window (UTC) | First packet 27/06/2017 13:38:32.234351 UTC, 17,239 packets in total (Wireshark status bar). Last packet 13:44:42.407776 UTC (capinfos shows 14:44:42 because the VM is on BST), so 370.17 s in total. | Confirmed | Wireshark, capinfos |
| HTTP requests in total | 643 (filter http.request) | Confirmed | E04 |
| Gateway MAC | Cisco_65:3b:c1 (00:07:0d:65:3b:c1) | Confirmed | E04 |
| NIC vendor | Wireshark resolves the host MAC as Dell_de:c7:3b, so it's a Dell machine | Confirmed | E03 |
| Conversations | 381 IPv4, 967 TCP, 729 UDP, only 3 Ethernet | Confirmed | E02 |
| Internal hosts | 192.168.1.96 is Address A in every IPv4 conversation. The only other local addresses are the gateway 192.168.1.1, broadcast 192.168.1.255 and multicast 224.0.0.252, so this is a single-host capture. | Confirmed | E02 |
| Largest conversations by packets | 59.106.164.230 (2,192 packets, ~3 MB inbound), 192.168.1.1 (1,364), 104.20.166.37 (1,212), 62.210.140.158 (710) | Confirmed | E02 |
| First external contact | 119.28.70.207 (matied.com): starts 0.20 s into the capture and stays active for ~319 s, the whole infection window | Confirmed | E02 |
| Scale of activity | 381 different IPv4 conversations in about 6 minutes from one workstation is far more than normal browsing | Confirmed | E02 |

## Infected host (Q1-Q3)
| Item | Value | Status | Evidence |
|---|---|---|---|
| MAC address | 00:15:c5:de:c7:3b (Dell_de:c7:3b), from the DHCP Client MAC address field | Confirmed | E03 |
| IP address | 192.168.1.96, from the DHCP Client IP address field | Confirmed | E03 |
| Hostname | FlashGordon-PC (DHCP option 12) | Confirmed | E03 |
| Operating system | Option 60 vendor class "MSFT 5.0", which is what Windows DHCP clients send, so it is a Windows machine | Confirmed | E03 |
| DHCP packets | Only 4: frame 213 Inform at 13:40:52 (ACK 214), frame 221 Inform at 13:43:49 (ACK 222). They're Informs (no Request anywhere), so the host already had its IP before the capture started. | Confirmed | E03 |

## Infection timeline (Q4-Q5)
| Frame | Time (UTC) | Event | Status | Evidence |
|---|---|---|---|---|
| 1 / 2 | 13:38:32.234 / .435 | DNS query for matied.com and the reply 119.28.70.207. This is the very first packet in the capture, so the download was the first thing the host did. | Confirmed | E20 |
| 6 | 13:38:32.652 | GET matied.com/gerv.gun, User-Agent "Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)". First HTTP request in the capture; the response is in frame 204. | Confirmed | E04, E05 |
| 298, 304 | 13:43:50-51 | POST to 119.28.70.207 /auth/ajax/847598782/?min=data and /auth/min/828949448/ (form-urlencoded). Same IP as the first download, about 5 minutes later: looks like the first payload checking in and sending data. | Confirmed | E04 |
| 866 | 13:43:58 | GET /img/t64.bin from 59.106.164.230. This IP is the largest conversation (~3 MB inbound), so t64.bin is probably another payload, possibly encoded. Check it at export. | Confirmed | E04 |
| 1423 onwards | 13:44:01+ | Burst of "POST / HTTP/1.1" requests to many different IPs within seconds, which is the start of the Pushdo C2 activity | Confirmed | E04 |
| 204 | 13:38:36.765 | 200 OK for gerv.gun, about 4 seconds after the request. Wireshark flags the last segment as TCP Out-Of-Order, but the response still reassembles. | Confirmed (E04b), body to check (E05) | E04b, E05 |
| 313 / 656 | 13:43:52.243 / 13:43:53.966 | GET lounge-haarstudio.nl/oud/trow.exe (145.131.10.21), 200 OK | Confirmed | E04b |
| 667 / 855 | 13:43:54.128 / 13:43:54.272 | GET vantagepointtechnologies.com/wp.exe (143.95.151.192), 200 OK served openly as application/x-msdownload | Confirmed | E04b |
| 866 / 5381 | 13:43:58.715 / 13:44:08.337 | GET /img/t64.bin (59.106.164.230), 200 OK about 10 seconds later | Confirmed | E04b |

### gerv.gun response, from Follow HTTP Stream (tcp.stream eq 0, E05)
- Server: nginx. Content-Type: application/octet-stream. Content-Length: 241664.
- Server Date header: Tue, 27 Jun 2017 13:38:33 GMT. It matches the pcap's UTC time to within a second, so the 13:38 UTC infection time is right and it's the Suricata timestamps that are off.
- Last-Modified: Mon, 26 Jun 2017 19:09:45 GMT. The payload was put on the server about 18 hours before the infection, so this was a fresh campaign.
- Body starts with "MZ" and contains "This program cannot be run in DOS mode", "PE", "Rich" and the section names .text, .rdata, .data and .rsrc. This is a normal Windows PE layout, so the .gun extension is just a disguise.
- The end of the body holds UTF-16 resource strings in Romanian for what looks like a video player's settings ("Sincronizare", "Gestionare culori", "Tip de intrare: HDTV/SDTV/NTSC/PAL", "seek bar"), plus a standard Windows manifest and PADDINGXX filler. So the file seems to pose as (or be built from) a legit media player, probably to look harmless (ATT&CK T1036 Masquerading). Only seen through strings though, so just an observation.
- The stream text wasn't saved as a file (E05_frame6_stream.txt is missing from outputs); the E05 screenshot covers it.

## Payloads (Q8-Q10)
| File | Size (bytes) | SHA256 | File type | Status |
|---|---|---|---|---|
| gerv.gun | 241,664 | 0931537889c35226d00ed26962ecacb140521394279eb2ade7e9d2afcf1a7272 | PE32 executable for MS Windows 4.00 (GUI), Intel i386, 4 sections | Confirmed (E09) |
| trow.exe | 330,752 | 94a0a09ee6a21526ac34d41eabf4ba603e9a30c26e6a1dc072ff45749dfb1fe1 | PE32 executable for MS Windows 5.00 (GUI), Intel i386, 4 sections | Confirmed (E09) |
| wp.exe | 307,712 | 79d503165d32176842fe386d96c04fb70f6ce1c8a485837957849297e625ea48 | PE32 executable for MS Windows 4.00 (GUI), Intel i386, 4 sections | Confirmed (E09) |
| t64.bin | 3,162,369 | 9875dac23b48fe6a52681b113be524a18c503df9b16081be73390ea18614ca68 | data (no recognisable file format) | Confirmed (E09) |

All four hashes were calculated in the VM and saved to outputs/E09_sha256.txt. The three executable hashes match the ones from my first pass on the host, which was done in memory without writing the files to disk, so two different methods give the same result.

t64.bin is not a recognisable file type, even though it's the biggest download. That suggests it is encrypted or encoded, probably an extra module or second stage that the malware decodes after download. I can't say what it is without reverse engineering, so I'll leave it as an open question in the report. It is not one of the "3 Windows executables" in the quiz. trow.exe targets a slightly newer Windows subsystem (5.00) than the other two (4.00), which hints that it was built separately, possibly a different family; I haven't confirmed that.

### Export Objects (HTTP), E08a-c
| Packet | Host | Content type | Size | File |
|---|---|---|---|---|
| 204 | matied.com | application/octet-stream | 241 kB | gerv.gun |
| 656 | lounge-haarstudio.nl | application/octet-stream | 330 kB | trow.exe |
| 855 | vantagepointtechnologies.com | application/x-msdownload | 307 kB | wp.exe |
| 5381 | rts21.co.jp | application/octet-stream | 3,162 kB | t64.bin |

t64.bin is by far the biggest download (about 3 MB) and comes from a Japanese domain, same as the Japanese phishing campaign. All four were saved to ~/cw1/quarantine and not opened. Sizes on disk: gerv.gun 241,664, trow.exe 330,752, wp.exe 307,712, t64.bin 3,162,369 bytes.

## VirusTotal lookups (hash search only, nothing uploaded), 11/11/2026
| File | Score | Popular threat label | Families / categories | Other | Evidence |
|---|---|---|---|---|---|
| gerv.gun (0931…7272) | 55/70 | trojan.shiotob/jaik | Families: shiotob, jaik, bebloh. Categories: trojan, banker, ransomware. | Size 236 KB, community score -267, 21 community comments. Behaviour tags: calls-wmi, idle, checks-bios, detect-debug-environment, direct-cpu-clock-access, runtime-modules, spreader, checks-user-input. Vendor names include TrojanBanker:Win32/Shiotob (Alibaba), Trojan.Banker.Shiotob (Jiangmin), Trojan.Win32.Banker (Gridinsoft), Win32/Kryptik.GALF (ESET). ALYac says Trojan.Ransom.LockyCrypt, which looks like an outlier. | E10a |
| trow.exe (94a0…1fe1) | 66/71 | trojan.cutwail/wigon | Families: cutwail, wigon, gen7. Categories: trojan, dropper. | Known on VT as "Pedals.exe", 323 KB, community score -85, 20 comments. Behaviour tags: checks-network-adapters, long-sleeps, persistence, detect-debug-environment, suspicious-dns, via-tor, spreader, idle, exploit, plus CVE tags 2016-2569, 2005-0446 and 2015-1729. Vendor names: TrojanDropper:Win32/Cutwail (Alibaba), Trojan/Win32.Cutwail (Antiy), Exe.trojan.cutwail (CTX), Win32/Wigon.PI (ESET), Trojan:Win/Wigon.PL (AliCloud), Trojan.DownLoad.64914 (DrWeb). | E10b |
| wp.exe (79d5…ea48) | 59/71 | trojan.ursnif/nymaim | Families: ursnif, nymaim, cerber. Categories: trojan, ransomware, spyware. | 300.5 KB, community score -12, 9 comments. Behaviour tags: corrupt, checks-cpu-name, spreader, detect-debug-environment, checks-user-input, persistence, long-sleeps, self-delete. VT Code Insights: an obfuscated crypter/loader that uses API hammering (repeated dummy calls) to get past emulation, then decrypts shellcode from its data section and runs it. Vendor names: Trojan/Win32.Ursnif (AhnLab), Backdoor:Win32/Ursnif (Alibaba), Trojan[Spy]/Win32.Ursnif (Antiy), Trojan.Gozi.24 (DrWeb), Generic.Nymaim (BitDefender, Arcabit), Exe.unknown.nymaim (CTX), Trojan.Ransom.Cerber (ALYac). | E10c |
| t64.bin (9875…ca68) | 0/62 | none | none | 3.02 MB, last analysed 7 months ago. Community score -27 (1 comment), so someone has marked it bad. 0 detections, but `file` couldn't identify it either (E09), so probably encrypted/encoded - AV can't match signatures on that, 0/62 doesn't mean safe. My guess: a module or config that one of the other payloads decrypts later. Frame 866 has no User-Agent at all (gerv.gun = WinHttp, trow/wp = IE8, centler.at check-ins = IE11), so a 4th HTTP client fetched it, probably code in one of the payloads. Can't tell which without reversing. | E10d |

What gerv.gun's result changes: the first payload is not Pushdo itself. Most vendors call it Shiotob, also known as URLZone / Bebloh, a banking trojan that also acts as a downloader. It was mainly used against Japanese users around 2016-2017 through JavaScript email attachments, so same as this Japanese campaign (also matches the Hybrid Analysis label "Trojan.Shiotob" I saw in my first OSINT search). So the infection seems to have two stages: the JS dropper installs Shiotob (gerv.gun), Shiotob checks in to centler.at on the same server and then pulls down more payloads, and one of those is the Pushdo spam bot that both IDS detected. The quiz answer for Q6 (based on the IDS alerts) is still PUSHDO, but the report needs to say the host was hit by a banking trojan as well, which is worse (banking credentials at risk). The tags "detect-debug-environment", "checks-bios" and "idle" mean it tries to spot sandboxes and can wait before acting, - could explain the 5-minute quiet gap in E19, but that's not proven. Which of trow.exe and wp.exe is Pushdo still has to be checked.

trow.exe answers that: it's Cutwail, which ESET calls Win32/Wigon. Pushdo and Cutwail are the same botnet; Pushdo is the loader and Cutwail is the spam engine, and the names are often used for the same malware. So trow.exe is the Pushdo/Cutwail spam bot behind the 637 C2 check-ins and the 155 mail-server connections. It also explains why trow.exe looked different in E09 (subsystem 5.00): it's a different family from gerv.gun. Two of its tags matter for my leads. "via-tor" means sandboxes have seen this sample use Tor, so at first I took this to mean the Tor connection to 208.83.223.34 came from trow.exe rather than from a separate Gozi infection, which would weaken the Gozi JA3 lead.

wp.exe changed that again. Most vendors call it Ursnif, and DrWeb calls it Gozi, which is another name for the same banking trojan. So a Gozi/Ursnif sample really was delivered to this host, and the JA3 "Possible Gozi" alert from the current ruleset was right after all. Some vendors say Nymaim or Cerber instead. That's probably because the crypter wrapped around the payload (the obfuscated loader VT describes) is shared between families and confuses some engines, so I'm going with the majority view of Ursnif/Gozi. Both Cutwail and Ursnif are known to use Tor, so I can't say for certain which of them made the 208.83.223.34 connection. What I can say is that the host received three different malware families in about five minutes.

Back to trow.exe: "persistence" plus "long-sleeps" mean it survives reboots and waits for long periods, so rebuild the machine, don't just clean it.

## JavaScript dropper (Q7)

VirusTotal results for the droppers:
| Hash | Score | Name on VT | Labels | Other | Evidence |
|---|---|---|---|---|---|
| 59727ea2…e702 | 43/59 | 2017-547805549-231.pdf.js, one of the three filenames from the Japanese campaign | Nemucod JavaScript downloader: JS/TrojanDownloader.Nemucod.DFS (ESET), TrojanDownloader:JS/Nemucod (Microsoft), JS/Dldr.Nemucod.DQ (Avira), JS.DownLoader.4004 (DrWeb), JS:Downloader-FDA (Avast/AVG) | Text file, 15.69 KB, last analysed 6 years ago, community score -102, 6 comments. VT shows no Relations or Behavior tab for it. However, the Community tab (E11c) has two automated comments from Hybrid Analysis (sandbox threat score 52/100) whose memory strings contain "matied.com/gerv.gun" and a second URL, "www.feuerwehr-brieselang.de/media/vector.tui", extracted from this script when it was run in a sandbox. That directly confirms this JS downloads gerv.gun from matied.com. feuerwehr-brieselang.de is probably a backup download location; it doesn't appear in my pcap because the first URL worked. Another comment links the myonlinesecurity.co.uk write-up of the Japanese invoice campaign. | E11a, E11c |
| 64ae1359…150f | 32/60 | doc.js (fits DOC0978043-2017.6.doc.js from the campaign) | Nemucod again: JS/TrojanDownloader.Nemucod.DFS (ESET), TrojanDownloader:JS/Nemucod (Microsoft), JS/Nemucod.DD3E!tr (Fortinet), JS.DownLoader.4009 (DrWeb), JS:Downloader-FDA (Avast/AVG) | Text, 16.71 KB, last analysed 6 years ago, community score -244, 9 comments. Same family and ESET signature (Nemucod.DFS) as the first one, and almost the same size, so they look like two variants of the same script sent in the same campaign. Community tab (E11d): Hybrid Analysis (threat score 52/100) again found "matied.com/gerv.gun" and "www.feuerwehr-brieselang.de/media/vector.tui" in memory, next to "saveToFile" fragments, so this script also downloads gerv.gun and saves it to disk. Another analyst (Antelox) tagged it "#URLZone javascript downloader". That matches the VT label for gerv.gun (Shiotob = URLZone), so the JS-to-Shiotob step is backed up by an independent analyst too. | E11b, E11d |

The blog post itself (E12) is dated 2017/06/27, the same day as the capture. It quotes the email text the victims received, e.g. subject "2017.6支払依頼書" (June 2017 payment request): "お疲れ様です。請求書金額を入力した支払依頼書を添付いたしました。ご確認後、印刷し原本のご郵送をお願い致します。" (roughly: "Thanks for your work. I have attached the payment request with the invoice amount filled in. Please check it, print it and post the original."). The email isn't in my pcap, so this is as close as I can get to what the user saw. Just a normal-looking business request to get them to open the attachment.

The hash section of the blog (E12b) lists three script files by MD5 with VirusTotal links: 60834d0c…f60e, 59727ea2…e702 and 64ae1359…150f, labelled ESET JS/TrojanDownloader.Nemucod, Microsoft TrojanDownloader:JS/Nemucod, Kaspersky Trojan.VBS.Agent, Symantec JS.Downloader and Trend Micro JS_NEMUCOD.ELDSAUHE. It also lists one executable, 0931537889c3…7272 (my gerv.gun), labelled Kaspersky Trojan-Banker.Win32.Shiotob and Microsoft TrojanSpy:Win32/Banker. So the Shiotob label was already used back in June 2017. The third script (60834d0c…) is probably the .xls.js variant; the tutor only accepts the other two for Q7, so I only list it as an extra OSINT IOC. The blog also suggests blocking wscript.exe from making network connections with the firewall, so that opening a .js file by mistake can't download anything. Cheap fix, add it to the recommendations.

The .pdf.js double extension is the trick: the file is meant to look like a PDF invoice but is really a script that Windows runs with Windows Script Host. That matches the WinHttp User-Agent of the first download.

Not in the pcap, so I found it through OSINT. The source below lists the same gerv.gun hash I recovered from the capture, which is what links the campaign to this incident.
- 59727ea201d94d471bdbb353b1281cca3c5bebf5305b140a3c017e52a37be702
- 64ae13592c5d8b289be81ebb50e054cef49b0bdf50ea92dd44ed611dd274150f
- Source: fireflyframer.blog.jp/19064394.html
- VirusTotal lookups done, results in the table above (E11a-d)

## IDS alerts (Q6)
| Item | Value | Status | Evidence |
|---|---|---|---|
| Snort totals | 673 alerts across 21 different signatures | Confirmed | E06 |
| Snort, MALWARE-CNC Win.Trojan.Pushdo variant outbound connection (sid 1:29891) | 498 alerts, about 74% of everything Snort raised | Confirmed | E06 |
| Snort, other notable signatures | 47 non-alphanumeric JavaScript obfuscation (1:23832), 41 SMTP command buffer overflow (124:1), 10 JavaScript unescape obfuscation (1:19887), 6 PE binary magic (1:15306), 2 download of executable content (1:11192), 3 suspicious .ru DNS query (1:15168), 1 Win.Trojan.Kazy (1:28406), 1 SENSITIVE-DATA email addresses (138:5) | Confirmed | E06 |
| Snort, protocol-anomaly noise | 16 + 9 http_inspect content-length issues, 9 SDF combination, 3 small TCP segments: just preprocessor alerts, nothing malware-specific | Confirmed | E06 |
| Suricata totals | 842 alerts across only 10 signatures | Confirmed | E07 |
| Suricata, ET TROJAN Backdoor.Win32.Pushdo.s Checkin | 823 alerts, about 98% of everything Suricata raised | Confirmed | E07 |
| Suricata, ET CURRENT_EVENTS WinHttpRequest Downloading EXE | 1 alert. Snort has no equivalent, so only Suricata picked up how the first download was made. | Confirmed | E07 |
| Suricata, other signatures | 5 PE EXE or DLL download, 5 binary under 1 MB likely hostile, 2 exe download via HTTP, 1 IE6 in use, 2 Sinkhole.tech reply, 1 Fitsec sinkhole IP, 1 Snkz sinkhole cookie, 1 Downadup/Conficker-C P2P | Confirmed | E07 |
| Snort vs Suricata, overall | Both name Pushdo as the main threat. Suricata was far less noisy (10 signatures against 21, with 98% of its alerts on Pushdo), caught the scripted download and flagged the outdated IE6 User-Agent, and also recognised the sinkholed C2. Snort gave more context about side effects (JavaScript obfuscation, SMTP) but with a lot of protocol noise. | Confirmed | E06, E07 |
| First and last Snort Pushdo alert | First at 13:44:11.994487 (192.168.1.96:49318 -> 104.20.221.29:80), last at 13:44:42.003628 (192.168.1.96:50139 -> 82.208.109.253:80), right at the end of the capture. The burst starts at frame 1423 (13:44:01.38), so Snort's first Pushdo alert comes about 10 s late and it missed the start. | Confirmed (CW1Snort.txt, sorted by time) | E06 |
| Suricata timestamp offset | Both first alerts are for the same packet (119.28.70.207:80 -> 192.168.1.96:49184, the gerv.gun download). Snort stamps it 06/27 13:38:34.111294, which matches the pcap; Suricata stamps it 2017-06-28 00:14:33. That's a difference of 10h35m59s, which isn't a timezone offset. Suricata's record also shows ttl=0, ID=0 and empty TCP fields, so its output looks like it was converted or replayed after capture and stamped with processing time. I used the pcap/Snort times. Snort doesn't print the year, so its date relies on the pcap. | Confirmed | E07b |
| Conficker alert (Suricata) | 192.168.1.96 -> 224.0.0.252, UDP 56075 -> 5355, TTL 1. Port 5355 to 224.0.0.252 is LLMNR, normal Windows local name resolution, so I treat this as a false positive. Nothing else in the capture points to Conficker. | Confirmed | E15 |
| Kazy alert (Snort 1:28406) | 13:43:54.128138, 192.168.1.96:49191 -> 143.95.151.192:80. That's exactly the time of frame 667, the GET for wp.exe, so it's just the wp.exe download under a generic name. No separate infection. | Confirmed | E15 |
| Sinkhole alerts (Suricata) | Sinkhole.tech reply x2 from 144.217.254.90:80 (to ports 49227 and 49231); Fitsec sinkhole IP x1, host connecting out to 193.166.255.171:80; Snkz sinkhole cookie x1 from 212.61.180.100:80. So some of the C2 domains the malware tried had already been taken over by researchers. The host is still compromised either way. | Confirmed | E15 |

## IOC extraction (outputs/ioc_*.txt, E23)
| List | Count |
|---|---|
| Unique DNS names queried | 403 (raw list, it also has junk like `com`, `de`, `org`, `wpad` and the Google/OpenDNS names, so not every name is an IOC) |
| HTTP requests | 643 |
| Different mail servers contacted on port 25 | 155 |
| IP endpoints (file lines, includes a few header lines) | 387 |
| Different User-Agents | 5 (one is empty) |

User-Agents seen from 192.168.1.96:
| Count | User-Agent | What I think it is |
|---|---|---|
| 637 | Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) | Pushdo C2 traffic. The fake IE6-on-XP identity matched by ET sid 2016867; 99% of all HTTP requests |
| 2 | Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko | IE11 on 64-bit Windows 7, the machine's real browser identity. Used for the two POSTs to 119.28.70.207 at 13:43:50, probably sent by the first payload through the normal Windows web libraries |
| 2 | Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1) | The trow.exe and wp.exe downloads |
| 1 | Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5) | The gerv.gun download by the JavaScript dropper |
| 1 | (empty) | One request without a User-Agent |

4 different browser identities from one PC in 6 minutes is suspicious by itself. The real one (Trident/7.0, Windows NT 6.1, WOW64) tells me the infected machine is most likely 64-bit Windows 7 with IE11, which makes the "Windows XP / IE6" identity in 99% of requests clearly fake. Each stage of the infection used its own HTTP client, so I can use the User-Agent to split the traffic into stages: script dropper, then payload downloads, then C2.

## Post-infection behaviour
| Item | Value | Status | Evidence |
|---|---|---|---|
| Traffic over time (I/O graph, 1-second intervals) | A small blip in the first few seconds (the gerv.gun download, 0-4 s), then almost nothing for about 5 minutes apart from background Windows broadcasts, then a sudden jump from about 318 s (13:43:50) with several peaks and a maximum of roughly 1,500-1,600 packets per second around 340 s (13:44:12), when the C2 burst and the SMTP connections overlap. TCP errors (red bars) appear almost only during the burst, probably all the short connections being opened, refused or retried. | Confirmed | E19 |
| Quiet gap | About 5 minutes and 14 seconds between gerv.gun arriving (13:38:36) and the first check-in to 119.28.70.207 (13:43:50). Some malware waits before acting to get past automated sandboxes, which only watch for a few minutes, but the gap could also be installation time or the user's activity. I'll mention it as a possible delay without claiming it was deliberate. | Interpretation | E19 |
| C2 burst with the IE6 User-Agent | 637 requests (filter http.user_agent contains "MSIE 6.0"). They start at frame 1423, 13:44:01.381, and in the first half-second there are already about 25 POSTs to 25 different IPs. Every one is "POST / HTTP/1.1" with Accept */*, Accept-Language en-us, Content-Type application/octet-stream, no Referer, and a body of around 600 bytes of random-looking (encrypted or encoded) data. Exactly what ET sid 2016867 looks for. The Host header is a different, ordinary-looking website each time (e.g. frame 1423: www.sjbs.org at 198.1.85.250). Known Pushdo trick: send the check-ins to hundreds of legit sites so the real C2 is hidden in the noise. These sites are only decoys and the attacker doesn't own them, so blocking all of them would be wrong. | Confirmed | E13 |
| Outbound SMTP connection attempts | 475 SYN packets to port 25 (counted in Wireshark), going to 155 different mail servers (E23), so many were retried. The first is frame 5490 at 13:44:11.850 to 157.112.145.19, about 10 seconds after the C2 burst began, and about 25 different servers are contacted within the first 0.15 seconds. A normal workstation shouldn't talk to outside mail servers on port 25 directly (its mail goes through the company server), so this is the spam bot (Pushdo's Cutwail spam module). | Confirmed | E14, E23 |
| SMTP server replies (filter smtp, 152 packets) | The mail servers that answered show who the spam was aimed at: several Mail.Ru (Russia), mx.google.com (Gmail), sakura.ne.jp and wpx.ne.jp (Japan), umcor.am (Armenia), home.net.pl (Poland), US hosting (inmotionhosting, rapidns), plus several "421 Connection was closed by peer" rejections. These are the mail providers of the people being spammed (a spam bot connects straight to each recipient's server). So Mail.Ru only means some targets had mail.ru addresses. Says nothing about where the attacker is. The Japanese servers fit the Japanese-language campaign that infected this host, so the bot may have been used to send the same phishing on to new victims. The 421 rejections suggest some servers already block this kind of traffic. | Confirmed | E14b |
| Client SMTP commands (filter smtp.req.command) | Only 2 packets, and neither is a real SMTP command. Frame 9521 (13:44:15) to 195.154.36.12:25 and frame 10944 (13:44:18) to 212.83.152.59:25 both contain binary data (\000\000\000... and non-printable bytes, 128 bytes reassembled), which Wireshark labels as SMTP only because of the port. No EHLO, MAIL FROM or RCPT TO appears anywhere in the capture. | Confirmed | E14c |
| What that means | Host tried 155 mail servers and got their greetings, but no spam actually gets handed over in the capture (maybe because it ends at 13:44:42, only ~30 s after SMTP starts). So in the report: "attempted spam" / spam-sending behaviour. Can't say "sent spam". 212.83.152.59 is interesting: E02 shows ~145 kB in from it and only ~3 kB out. Big download over port 25 from something that doesn't speak SMTP - my guess is the spam module pulling its templates/address lists over a custom protocol on port 25 to blend in. Can't decode it, so hypothesis only. | Interpretation | E14c, E02 |
| Server banner times | e.g. inmotionhosting "Tue, 27 Jun 2017 09:44:12 -0400" and sakura.ne.jp "22:44:12 +0900 (JST)" are both 13:44:12 UTC, which matches the pcap again | Confirmed | E14b |
| Unique DNS names queried | 403 unique names; 857 name queries in total including LLMNR (filter dns.flags.response==0) | Confirmed | E20, E23 |
| DNS order of events | 13:38:32 matied.com (frame 1, the very first packet). 13:40:52 and 13:43:49 "wpad" over LLMNR to 224.0.0.252: Windows looking for a proxy auto-config file, which is normal Windows behaviour and explains the false "Conficker" alert. 13:43:49.21 www.google.com, probably the malware checking it has internet access. 13:43:49.69 centler.at: the domain behind the 13:43:50 POSTs, and it resolves to 119.28.70.207, the same IP as matied.com, so the dropper site and the first check-in share infrastructure. 13:43:51.8 lounge-haarstudio.nl (trow.exe). 13:43:54.0 vantagepointtechnologies.com (wp.exe). 13:43:58.4 rts21.co.jp (t64.bin). 13:44:01.28: a dozen unrelated domains (www.mobilnic.net, www.reglera.com, www.transsib.com, www.nelipak.nl, www.elpro.si, www.ex-olive.com, www.sjbs.org, ...) looked up within about 2 milliseconds, the decoy list for the C2 burst. 13:44:01.39 resolver1.opendns.com, then the myip.opendns.com public-IP check. | Confirmed | E20 |
| Protocol split | 17,239 packets, 12.1 MB. By packets: TCP 87.1%, UDP 12.9%. Within that (Wireshark numbers; outputs/protocol_hierarchy.txt is from single-pass TShark and gives HTTP 1,233, SMTP 150 and no malformed packet): HTTP 1,230 packets (7.1%), DNS 1,401 (8.1%), NBNS 684 (4.0%), SMTP 152 (0.9%), LLMNR 127 (0.7%), TLS 44 (0.3%), DHCP 4, 1 malformed packet. By bytes it's mostly HTTP content: "Line-based text data" (523 web responses, 4.9 MB, 40.3%) and "Data" (640 bodies, 4.3 MB, 35.9%). The 640 Data bodies are basically the 637 C2 POSTs, and the 523 text responses are mostly HTML from the decoy sites, so most of the volume is botnet traffic. Only 44 TLS packets - nearly everything malicious was plain HTTP, which is why the IDS and my rules could see it. | Confirmed | E18 |

## Detection testing
| Test | Expected | Result | Evidence |
|---|---|---|---|
| Current ET ruleset against the pcap | Pushdo still detected; compare counts with the 2017 output | Suricata 8.0.3 read all 17,239 packets (12,113,758 bytes). 89 alerts across 16 signatures, against 842 in the 2017 output. Pushdo.s Checkin fired only once (823 in 2017) because of the 10-minute threshold on sid 2016867, so my prediction from E16 was right. Pushdo.S CnC response also fired once, so the C2 server's reply was matched too. | E21a, E21b |
| My rule sid 1000001 (WinHttp User-Agent) | Fires once (gerv.gun) | Fired once: host:49184 -> 119.28.70.207:80, the gerv.gun request. The alert time is 13:38:34.11 UTC rather than 13:38:32.65 when the request was sent, because Suricata only inspects the request once the TCP stream has been reassembled, a little later. | E17 |
| My rule sid 1000002 (MZ in HTTP response) | Fires three times | Fired exactly three times: 119.28.70.207 (gerv.gun, 13:38:34), 145.131.10.21 (trow.exe, 13:43:52), 143.95.151.192 (wp.exe, 13:43:54). It didn't fire on t64.bin (not a PE) or on any of the other ~640 HTTP objects. | E17 |

Both rules worked on this capture, no false positives. On a real network they'd need more work: sid 1000001 would also fire on legitimate scripts and admin tools that use WinHttp, and sid 1000002 fires on every executable downloaded over plain HTTP, which could be a lot in a big organisation. Combining them (an executable downloaded by a WinHttp script, or an executable served with a non-.exe extension) would be much more precise. They also only work on unencrypted HTTP; the same download over HTTPS would be invisible to both.

## Mistakes and corrections during the analysis
- While exporting the payloads I clicked "Save All" in the Export Objects dialog, assuming it would only save the rows matching my text filter. It actually saved every HTTP object in the capture (around 640 files, mostly the botnet's "POST /" bodies, saved as %2f, %2f(1) and so on) into the quarantine folder. I removed everything except the four files I needed with `find . -type f ! -name ... -delete` and checked with `ls -l` that only gerv.gun, trow.exe, wp.exe and t64.bin were left. No harm was done since the VM was isolated, but lesson learned: it's very easy to pull way more malicious stuff out of a pcap than you meant to. In a real case this would have to go in the evidence log.

## Pushdo rules in the current ET Open ruleset (E16)
| sid | Enabled | Name | What it matches |
|---|---|---|---|
| 2019235 | No (#) | ET MALWARE Pushdo v3 Checkin | Raw TCP to port 443/HTTP, 20-byte payload starting 02 00 00 00 |
| 2007771 | Yes | ET MALWARE Pushdo Update URL Detected | URI containing "/40E800" and "C00000" |
| 2015807 | Yes | ET MALWARE Backdoor.Win32.Pushdo.s Checkin | POST with a 39-character URI of the form /?ptrxcz_ plus 30 letters or digits |
| 2008493 | No (#) | ET MALWARE Pushdo Checkin | GET with m=, &a= and &os= followed by 50 hex characters |
| 2016867 | Yes | ET MALWARE Backdoor.Win32.Pushdo.s Checkin | POST with the exact User-Agent "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)", Accept */*, Accept-Language en-us, Content-Type application/octet-stream, the headers in a fixed order and no Referer. Sets the flowbit ET.Pushdo.S. Has threshold "limit, by_src, count 1, seconds 600", so it now alerts at most once per host every 10 minutes. |
| 2018897 | Yes | ET MALWARE Pushdo.S CnC response | Server reply (needs flowbit ET.Pushdo.S) with X-GeoIP-Country-Code and X-Real-IP headers. Marked former_category RETIRED. |

What I take from this:
- The 2017 alert name "ET TROJAN Backdoor.Win32.Pushdo.s Checkin" is now "ET MALWARE ..."; ET renamed the category, the detection is the same family.
- sid 2016867 describes exactly the burst I saw in E04 from frame 1423: many "POST / HTTP/1.1" requests to different IPs. So that burst is the Pushdo check-in traffic, with an old IE6-on-XP User-Agent hard-coded into the malware (the host itself is newer Windows, so the UA is fake).
- Because of the threshold, the current rule should alert once per 10 minutes rather than once per request. That's probably why the 2017 output has 823 alerts. So the number of alerts says more about rule tuning than about how bad the infection is. To test in E21.
- Detection is based on fixed details of the malware's HTTP requests (User-Agent, header order, URI format). That works for this variant but is easy for the authors to change, which is probably why two of the older Pushdo rules are now disabled.

## Current ruleset results in detail (E21b)
| Count | Signature | My reading |
|---|---|---|
| 40 | SURICATA Applayer Detect protocol only one direction | Engine/protocol noise |
| 28 | SURICATA HTTP Response excessive header repetition | Engine/protocol noise |
| 4 | ET INFO Observed DNS Query to .biz TLD | Lookups of suspicious domains |
| 3 | ET INFO PE EXE or DLL Windows file download HTTP | Exactly the three executables |
| 2 | ET INFO HTTP Request to a *.tw domain | Request to a Taiwanese domain, to check |
| 2 | ET INFO External IP Lookup Domain (myip.opendns.com) | Malware checking its own public IP, typical for bots before sending spam or reporting in |
| 1 | SURICATA HTTP invalid response field folding | Noise |
| 1 | ET MALWARE Terse alphanumeric executable downloader high likelihood of being hostile | Probably one of the downloads |
| 1 | ET MALWARE Pushdo.S CnC response | Pushdo C2 reply |
| 1 + 1 | ET MALWARE Possible Compromised Host AnubisNetworks Sinkhole Cookie Value btst / Snkz | Sinkholed C2, as in 2017 |
| 1 | ET MALWARE Backdoor.Win32.Pushdo.s Checkin | Pushdo check-in (thresholded) |
| 1 | ET JA3 Hash - [Abuse.ch] Possible Gozi | TLS client fingerprint matching Gozi/Ursnif, a banking trojan. Not in the 2017 output. |
| 1 | ET INFO WinHttpRequest Downloading EXE | The scripted first download, same as 2017 |
| 1 | ET INFO TLS possible TOR SSL traffic | Possible Tor traffic. Not in the 2017 output. |
| 1 | ET INFO Packed Executable Download | One payload is packed (compressed or obfuscated) |

Which connections triggered the new alerts (E21c). Times below are shown by the current Suricata in the VM's local time (BST); subtract one hour for UTC.
| Time (UTC) | Alert | Connection | My reading |
|---|---|---|---|
| 13:38:34 | Packed Executable Download | 119.28.70.207:80 -> host:49184 | gerv.gun itself is packed |
| 13:43:54 | Terse alphanumeric executable downloader | host:49191 -> 143.95.151.192:80 | The wp.exe request, the same connection Snort called "Kazy" |
| 13:44:01 | External IP Lookup (myip.opendns.com) x2 | host -> 208.67.222.222:53 (OpenDNS) | The malware checks its own public IP at the exact moment the C2 burst starts |
| 13:44:19 and 13:44:40 | HTTP Request to a *.tw domain | host -> 104.27.159.122:80 | Requests to a Taiwanese domain behind a CDN IP; domain name to check |
| 13:44:32 | JA3 Possible Gozi, and TLS possible TOR SSL traffic | host:49932 <-> 208.83.223.34:80 | TLS on port 80 instead of 443, which is unusual. E02 shows this IP as a short (1.4 s) conversation with about 681 kB coming in, so it looks like a quick encrypted download. It is a different server from the ones that sent trow.exe and t64.bin. |

Both "new" alerts point to the same single connection to 208.83.223.34. Encrypted traffic on a non-standard port (ATT&CK T1571), a Gozi-like TLS fingerprint and a large inbound transfer together make a reasonable case for a second-stage download, but I can't see inside it, so it stays a lead.

TLS handshake with 208.83.223.34 (E21d, decoding port 80 as TLS):
| Frame | Time (UTC) | Direction | Handshake | SNI |
|---|---|---|---|---|
| 14744 | 13:44:32.792 | host -> 208.83.223.34 | Client Hello (1) | www.kid67ap2i5b5d4ekvcg.com |
| 14765 | 13:44:32.862 | server -> host | Server Hello, Certificate, Server Key Exchange, Server Hello Done (2,11,12,14) | |
| 14770 | 13:44:32.873 | host -> server | Client Key Exchange (16) | |
| 14794 | 13:44:32.945 | server -> host | end of handshake | |

SNI is a random "www.<random>.com" name, which is what Tor clients send to a relay. So Suricata's "possible TOR" is probably right and 208.83.223.34 is a Tor relay on port 80. ~681 kB in 1.4 s could be the Tor client grabbing the directory on first start, can't confirm (encrypted). Some Gozi/Ursnif versions use Tor for C2, so the Tor hit and the Gozi JA3 back each other up. Still only a lead for now.

Tool note: tshark in the VM refused to open the pcap by name ("You don't have permission to read the file") even though Wireshark opened it fine, probably because of Ubuntu's AppArmor profile for tshark. Piping the file in (`cat COMP3010CW1.pcap | tshark -r - ...`) worked.

The current Suricata stamps alerts with the real packet time (shown in local BST). That supports my view that the 2017 Suricata file's +10h36m offset came from however that output was produced, because current Suricata gets the times right.

The two new leads are the Gozi JA3 match and the possible Tor traffic. Gozi (also called Ursnif) is a banking trojan, and Pushdo campaigns are known to drop it as a second payload. It could explain t64.bin (encrypted) or trow.exe (built differently from the others). A JA3 fingerprint on its own is weak evidence, because many programs share the same TLS fingerprint, so for now it's a possible second infection that needs checking.

## For the report
- Two of the six Pushdo rules in the current ET ruleset are disabled by default, so an out-of-the-box Suricata install today would not necessarily match every Pushdo variant. So just installing the IDS isn't enough, the ruleset needs tuning too.

## Screenshot checklist
| ID | Shows | Done |
|---|---|---|
| E00 | TShark version and groups (environment) | Yes |
| E16a | Suricata version, ruleset size, Pushdo rule count | Yes |
| E01 | pcap hash and isolation | Yes |
| E02 | IPv4 conversations | Yes |
| E03 | DHCP host details, incl. Option 60 "MSFT 5.0" (Windows) | Yes |
| E04 / E04b | First request / downloads with responses | Yes / Yes |
| E05 | Frame 6 HTTP stream | Yes |
| E06 / E07 | Snort / Suricata alert counts | Yes / Yes |
| E08a-d / E09 | Export objects (gun, exe, t64, clean-up) / hashes and file type | Yes / Yes |
| E13 / E14 / E15 | C2 burst / SMTP / false positive and sinkholes | Yes / Yes / Yes |
| E14b | SMTP server banners (who the spam was aimed at) | Yes |
| E14c | Binary (non-SMTP) data sent to port 25 | Yes |
| E07b | Snort vs Suricata timestamp for the same packet | Yes |
| E16 / E17 | Pushdo rule text / custom rules | Yes / Yes |
| E18 / E19 / E20 | Protocol hierarchy / I/O graph / DNS | Yes / Yes / Yes |
| E21a / E21b / E21c / E21d | Suricata run / current ruleset counts / new-lead details / 208.83.223.34 TLS check | Yes / Yes / Yes / Yes |
| E22 | Clean-up: quarantine deleted at 22:03, outputs listed | Yes |
| E23 | IOC list counts and User-Agent breakdown | Yes |
| E10a-d / E11a-d / E12a-b | VirusTotal: gerv.gun, trow.exe, wp.exe, t64.bin / JS hashes and comments / OSINT blog (date + email lure, hash list) | Yes / Yes / Yes |
