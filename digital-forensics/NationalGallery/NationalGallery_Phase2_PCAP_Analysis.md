# National Gallery DC 2012 — Digital Forensic Investigation Report
## Phase 2: Network Traffic (PCAP) Analysis

**Investigator:** Stephen Wambui  
**Date:** June 27, 2026  
**Evidence Source:** digitalcorpora.org — 2012 National Gallery DC Scenario  
**Case Type:** Insider Threat | Art Theft | Defacement Conspiracy  
**Phase:** 2  — PCAP Analysis

---

## 1. EVIDENCE ANALYZED

| File | Size | Network | Date |
|---|---|---|---|
| ngdc-interior-2012-07-06.pcap | 36M | Staff/Internal | July 6, 2012 |
| ngdc-interior-2012-07-09.pcap | 39M | Staff/Internal | July 9, 2012 |
| ngdc-interior-2012-07-10.pcap | 25M | Staff/Internal | July 10, 2012 |
| ngdc-exterior-2012-07-06.pcap | 143M | Visitor/External | July 6, 2012 |
| ngdc-exterior-2012-07-09.pcap | 45M | Visitor/External | July 9, 2012 |
| ngdc-exterior-2012-07-10.pcap | 37M | Visitor/External | July 10, 2012 |

---

## 2. NETWORK ARCHITECTURE

Two separate private networks identified at the gallery:

| Network | IP Range | Purpose |
|---|---|---|
| Interior | `192.168.1.x` | Staff/internal network |
| Exterior | `10.10.1.x` | Visitor/public WiFi network |

### Key Devices Identified:

| IP Address | Network | Device |
|---|---|---|
| `192.168.1.101` | Interior | Tracy's work Windows PC |
| `192.168.1.100` | Interior | Another gallery staff machine |
| `192.168.1.1` | Interior | Gateway/Router |
| `10.10.1.169` | Exterior | Suspect visitor device (3 days) |
| `184.106.117.171` | External | Rackspace hosted server |
| `213.139.122.103` | External | Unknown — under investigation |

---

## 3. TOOLS AND COMMANDS USED

| Tool | Purpose |
|---|---|
| `tshark` | Terminal-based packet analysis |
| `-r` flag | Read pcap file |
| `-T fields` | Extract specific fields only |
| `-e http.host` | Extract HTTP host header |
| `-e ip.src/dst` | Extract source/destination IPs |
| `-e dns.qry.name` | Extract DNS queries |
| `-e eth.src` | Extract MAC address |
| `sort \| uniq -c` | Count unique occurrences |
| `grep` | Filter specific patterns |

---

## 4. PROTOCOL ANALYSIS

### Interior Networks:
| Protocol | Significance |
|---|---|
| HTTP (100%) | All web traffic unencrypted — fully readable |
| OCSP (1%) | SSL certificate validation |

### Exterior Network (July 6):
| Protocol | Count | Significance |
|---|---|---|
| TCP | 119,575 | Base transport layer |
| ARP | 15,694 | Device discovery |
| HTTP | 2,659 | Readable web traffic |
| TLSv1 | 2,530 | Encrypted HTTPS — Rackspace traffic hidden here |
| SSH | 116 | Encrypted remote access — suspicious! |
| DNS | 1,039 | Domain lookups |

---

## 5. INTERIOR NETWORK FINDINGS

### 5.1 July 6, 2012 — Interior (Tracy's Work PC)

**Top domains visited from `192.168.1.101`:**

| Visits | Domain | Significance |
|---|---|---|
| 133 | www.momastore.org | Art museum store research |
| 125 | www.guggenheim.org | Guggenheim research |
| 111 | www.louvre.fr | Louvre research |
| 60 | www.nga.gov | National Gallery own site |
| 59 | www.moma.org | MoMA research |
| 17 | www.youtube.com | Terry's YouTube activity |
| 11 | www.bing.com | Tracy's searches |

**Key Finding — Museum Reconnaissance:**
Tracy browsed multiple major international art museums
from her work PC. Specific pages accessed on NGA:

```
/ginfo/ebmaps.shtm        — East Building maps page
/Online%20Tours           — Gallery online tours
/Art-Online%20Tours       — Art tours index
```

**Guggenheim specific pages accessed:**
```
/new-york/exhibitions/on-view/kandinsky    — Kandinsky exhibit
/art-of-another-kind                       — Specific exhibition
/international-abstraction                 — Art category
```

Visiting specific exhibit pages of competing museums
suggests research into high-value artwork, consistent
with intelligence gathering for the stamp theft conspiracy.

---

### 5.2 July 9, 2012 — Interior (Tracy's Work PC)

**Top domains visited:**

| Visits | Domain | Significance |
|---|---|---|
| 86 | www.blogto.com | Toronto city blog |
| 72 | img.agoda.net | Hotel booking images |
| 42 | mumbai.burrp.com | Mumbai India directory |
| 41 | www.agoda.com | Hotel booking site |
| 32 | www.youtube-nocookie.com | YouTube |
| 27 | www.facebook.com | Social media |

**Key Finding — Travel Planning:**
Tracy researched hotels in Manila, Philippines via Agoda:

```
agoda.com/Asia/Philippines/Manila/
hotels_near_national_gallery
```

Authentication tokens captured:
```
/maps/api/jsv2/AuthenticationService.Authenticate
token=127712
/maps/api/jsv2/QuotaService.RecordEvent
```

Active Agoda login session confirmed — not just browsing
but actively booking hotels near National Gallery Manila.
This indicates planned travel, possibly escape route
after stamp theft execution.

**Note:** July 9 is the same day Tracy zipped and
encrypted gallery documents on her home MacBook Air.

---

### 5.3 July 10, 2012 — Interior (Tracy's Work PC)

**Top domains visited:**

| Visits | Domain | Significance |
|---|---|---|
| 264 | b.mail.google.com | 🚨 Active Gmail session! |
| 141 | mail.google.com | Gmail |
| 150 | images.nga.gov | NGA gallery images |
| 112 | plus.google.com | Google Plus |
| 98 | maps.google.com | Google Maps |
| 28 | www.nga.gov | National Gallery site |
| 38 | www.bing.com | Bing searches |

**Key Finding 1 — Active Gmail Session:**
Tracy accessed Gmail from her work PC on July 10.
Session ID `457A534DFE7DC72B60AID=516` captured repeatedly,
confirming sustained logged-in Gmail session.

This is the same day she sent the encrypted zip to Pat
from her home MacBook — likely checking Pat's response
from her work machine.

**Key Finding 2 — East Building Floor Maps Downloaded:**

```
www.nga.gov    /ginfo/ebmaps.shtm
www.nga.gov    /images/maps/ebground.gif
www.nga.gov    /images/maps/ebmezzanine.gif
www.nga.gov    /images/maps/ebconcourse.gif
www.nga.gov    /images/maps/ebupperlevel.gif
www.nga.gov    /images/maps/ebtower.gif
www.nga.gov    /images/maps/ebmapkey.gif
www.nga.gov    /images/maps/men.gif
www.nga.gov    /images/maps/women.gif
www.nga.gov    /images/maps/family.gif
```

**eb = East Building** — Tracy downloaded EVERY floor
of the East Building:
- Ground floor
- Mezzanine level
- Concourse
- Upper level
- Tower
- Map key

This constitutes pre-operation reconnaissance —
blueprinting the gallery for the stamp theft.
The complete floor plan would allow Pat and King
to plan exact entry routes, stamp locations,
and escape paths.

---

## 6. EXTERIOR NETWORK FINDINGS

### 6.1 Device 10.10.1.169 — Primary Suspect Device

A single device consistently identified across all
three exterior capture days using MAC address verification.

**Same MAC address confirmed across:(08:00:27:ef:f7:f8)**
- July 6 exterior PCAP
- July 9 exterior PCAP  
- July 10 exterior PCAP

This proves the **same physical device** visited the
gallery exterior network on three separate days.

---

### 6.2 July 6, 2012 — Exterior (`10.10.1.169`)

**Key Finding — Steganographic Communication Channel:**

Device `10.10.1.169` accessed a specific Tumblr account:
```
chickswithstevebuscemeyes.tumblr.com
```

Multiple images downloaded from this account:
```
25.media.tumblr.com /tumblr_llefeq0zaN1qij8bto1_500.jpg
25.media.tumblr.com /tumblr_lkd9jbX1J21qij8bto1_500.jpg
25.media.tumblr.com /tumblr_lkakc49f7j1qij8bto1_r2_500.jpg
25.media.tumblr.com /tumblr_lk8cwpnnTF1qij8bto1_500.jpg
25.media.tumblr.com /tumblr_lk5wjcUfuj1qij8bto1_500.jpg
```

All images share identifier `qij8bto1` — same account owner.

**Significance:**
- Only ONE specific Tumblr account visited — deliberate
- Carry is known to use steganography per case description
- Tumblr is an image-sharing platform
- Images likely contain hidden steganographic messages
- This is a pre-arranged covert communication channel
  between Carry and Alex

**Rackspace traffic from exterior:**
- `184.106.117.171` received 66,876 packets
- Traffic encrypted via TLSv1
- Could be Carry uploading steg files to Rackspace server

**SSH activity detected:**
- 116 SSH packets on exterior network
- Remote access to `10.10.1.160`
- Possible remote command and control activity

---

### 6.3 July 9, 2012 — Exterior (`10.10.1.169`)

**Top domains identical to interior July 9:**
- Same Agoda/Manila research
- Same blogto.com traffic
- Same mumbai.burrp.com

**Key Finding:**
No Tumblr activity on July 9 — device behavior shifted
from covert communications (Jul 6) to travel planning.
Manila hotel research now confirmed on visitor device,
separate from Tracy's work PC activity.

**DHCP Note:**
While IP `10.10.1.169` appears on both July 6 and July 9,
MAC address comparison confirms same physical device —
ruling out coincidental IP reuse by different visitors.

---

### 6.4 July 10, 2012 — Exterior (`10.10.1.169`)

**Top domains mirror interior July 10:**

| Visits | Domain |
|---|---|
| 264 | b.mail.google.com |
| 137 | mail.google.com |
| 57 | images.nga.gov |
| 98 | maps.google.com |
| 28 | www.nga.gov |

**Key Finding — NGA Maps on Visitor Device:**
Same East Building floor map downloads seen on interior
now also appearing on exterior visitor device.

This suggests the visitor device user was coordinating
with Tracy — either receiving forwarded map files or
independently downloading same gallery maps.

---

## 7. CROSS-NETWORK CORRELATION

| Date | Interior Activity | Exterior Activity | Correlation |
|---|---|---|---|
| Jul 6 | Museum research, NGA tours | Tumblr steg, Rackspace | Separate actors, same day |
| Jul 9 | Manila/Agoda, doc zipping | Manila/Agoda research | Possible coordination |
| Jul 10 | Gmail session, floor maps | Gmail, floor maps | Highly correlated — same content |

---

## 8. KEY NETWORK EVIDENCE SUMMARY

### 8.1 Tracy's Work PC (`192.168.1.101`):
- Researched major art museums — intelligence gathering
- Browsed NGA online tours — internal reconnaissance
- Downloaded ALL East Building floor maps — blueprinting
- Active Gmail session July 10 — communicating with Pat
- Agoda Manila hotel search July 9 — escape planning

### 8.2 Visitor Device (`10.10.1.169`):
- Same physical device across 3 days (MAC confirmed)
- Accessed steganographic Tumblr channel July 6
- Manila travel research July 9
- NGA floor maps July 10
- Strongly suspected to be Carry's device — pending
  confirmation via mobile device forensics (Phase 3)

### 8.3 Rackspace Server (`184.106.117.171`):
- Dominant external IP in exterior capture
- 66,876 packets — heavy encrypted traffic
- TLSv1 encrypted — content not readable
- Likely hosting covert communication infrastructure

---

## 9. LIMITATIONS AND PENDING CONFIRMATIONS

| Finding | Status | Confirmation Method |
|---|---|---|
| `10.10.1.169` = Carry's device | Suspected | Match MAC to Carry's phone/tablet  |
| Rackspace content | Unknown | SSL keys needed to decrypt TLSv1 |
| Gmail session identity | Suspected Tracy | Email header analysis |
| Manila trip purpose | Unknown | Phone forensics Phase 3 |
| SSH remote access target | Unknown | Further packet analysis |

---

## 10. TIMELINE UPDATE — NETWORK ACTIVITY

| Date | Time | Actor | Network Activity |
|---|---|---|---|
| Jul 6 2012 | Morning | Tracy (192.168.1.101) | Museum research, NGA online tours |
| Jul 6 2012 | Afternoon | Carry (10.10.1.169) | Tumblr steg channel, Rackspace uploads |
| Jul 6 2012 | ~13:00 | Tracy + Carry | Physical lunch meeting |
| Jul 9 2012 | Morning | Tracy (192.168.1.101) | Manila hotel research, Agoda login |
| Jul 9 2012 | Afternoon | Unknown (10.10.1.169) | Same Manila research on visitor network |
| Jul 10 2012 | Morning | Tracy (192.168.1.101) | Gmail session, East Building floor maps |
| Jul 10 2012 | Unknown | Carry (10.10.1.169) | NGA floor maps on visitor network |

---

## 11. CONCLUSION

Phase 2 PCAP analysis significantly strengthens the
evidence base established in Phase 1. Network traffic
confirms Tracy was actively conducting intelligence
gathering from her gallery work PC — researching artwork,
downloading floor plans, and maintaining Gmail
communications with Pat.

The exterior visitor network reveals a second actor
using the same device across three gallery visits.
The combination of steganographic Tumblr communications,
Manila travel planning, and NGA floor map downloads
on this device strongly implicates Carry as the visitor
conducting parallel reconnaissance operations.

The two plots are clearly visible in the network data:
- Interior network = Tracy's insider operations
- Exterior network = Carry's defacement reconnaissance

Phase 3 mobile device forensics is critical to confirm
the identity of `10.10.1.169` by matching its MAC address
against Carry's seized phone and tablet.

---

*Report generated on @darkbyte *
