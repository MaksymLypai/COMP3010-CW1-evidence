# Incident timeline (UTC, 27 June 2017)

Times from the pcap. Snort, the HTTP `Date` header and SMTP server banners agree with them; the 2017 Suricata file is 10h36m ahead (E07b).

| Time | Frame(s) | Event | Evidence |
|---|---|---|---|
| before 13:38 | - | User opens a zipped `.pdf.js` / `.doc.js` attachment (Nemucod) from a Japanese "payment request" email | E11, E12 |
| 13:38:32.234 | 1-2 | DNS lookup matied.com -> 119.28.70.207 (first packet in the capture) | E20 |
| 13:38:32.652 | 6 | `GET /gerv.gun`, User-Agent WinHttp.WinHttpRequest.5 | E04, E05 |
| 13:38:36.765 | 204 | gerv.gun received: 241,664-byte PE32 (Shiotob/URLZone) | E05, E09, E10a |
| 13:38:36-13:43:49 | - | About 5 minutes of near silence | E19 |
| 13:40:52 | 213 | DHCP Inform: FlashGordon-PC, 00:15:c5:de:c7:3b | E03 |
| 13:43:49.69 | 291 | DNS centler.at -> 119.28.70.207 (same IP as matied.com) | E20 |
| 13:43:50-51 | 298, 304 | POSTs to centler.at /auth/... with the real IE11 User-Agent | E04 |
| 13:43:52-53 | 313 / 656 | trow.exe from lounge-haarstudio.nl (Pushdo/Cutwail) | E04b, E10b |
| 13:43:54 | 667 / 855 | wp.exe from vantagepointtechnologies.com (Ursnif/Gozi) | E04b, E10c |
| 13:43:58-13:44:08 | 866 / 5381 | t64.bin (3 MB, encrypted) from rts21.co.jp, no User-Agent | E04b, E10d |
| 13:44:01.28 | 1368+ | A dozen decoy domains looked up within ~2 ms | E20 |
| 13:44:01.38 | 1423+ | Pushdo C2 burst: 637 POSTs with fake IE6/XP User-Agent | E13 |
| 13:44:01.4 | - | Public-IP check via myip.opendns.com | E21c |
| 13:44:11.85 | 5490+ | 475 SYNs to port 25 on 155 mail servers | E14 |
| 13:44:15 / 13:44:18 | 9521, 10944 | Binary (non-SMTP) data to port 25 | E14c |
| 13:44:32.79 | 14744 | TLS Client Hello on port 80 to 208.83.223.34, Tor-style SNI | E21d |
| 13:44:42 | - | End of capture | |
