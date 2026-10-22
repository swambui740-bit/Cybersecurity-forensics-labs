# First to Last: Incident Report (2026-08-09)

Analysis of the [First to Last](https://www.malware-traffic-analysis.net/2026/08/09/index.html) traffic analysis exercise from malware-traffic-analysis.net.

## Summary

IDS alerts flagged FormBook C2 check-ins (HTTP GET, port 80) between 02:13 and 02:16 UTC on the `172.16.8[.]0/24` network (domain `firsttolast[.]tech`). The packet capture was analysed in Wireshark to identify the infected Windows client.

## The enviroment

|  |  |
| - | - |
| lan segment | 172.68.0/24- |
| Domain | firsttolast.tech |
| AD enviroment | FIRSTTOLAST |
| AD domain controller | 172.16.8.2-firsttolast-DC |
| Lan Gateway | 172.76.8.1 |
| LAN broadcast address | 172.16.8.255 |


## Answers

| Question | Answer |
| - | - |
| IP address of the infected Windows client | `172.16.8.49` |
| MAC address of the infected Windows client | `00:12:f0:28:d4:34` |
| Host name of the infected Windows client | `DESKTOP-5NLV63K` |
| User account name | `Vance` |
| Full name of the user | `Rymond Vance` |


## Step-by-step analysis

### Step 1: Identify the infected IP address

Filter used:

```
http.request.method == GET
```

`found the ip was in communication with the servers highlighted by the alerts and the get request were unusual and directly to alerting port, the request were encoded which made them suspicious`.


### Step 2: Identify the MAC address

Filter used:

```
http.request.method == GET
```

`by filtering this and referencing to the infected machine ip and locating source mac address in the ethernet II packet details`.


### Step 3: Identify the host name

Filter used:

```
nbns && ip.src == 172.16.8.49
```

`analysed the protocol and in the query  packets found the username refered above`.


### Step 4: Identify the user account name

Filter used:

```
samr.samr_userinfo21.full_name
```

`expanding the packet details for samr protocol i obtain the name "Vance" that was associated with the account since it was on AD(active directory) enviroment`



### Step 5: Identify the user's full name

Filter used:

```
samr.samr_userinfo21.full_name
```

`expanding the protocol packet detail i obtained the full name "Rymond vance" in the full name field`


## Conclusion

Host `<hostname>` (`172.16.8.49`, `00:12:f0:28:d4:34`), used by `<Rymond Vance>`, is infected with malware matching the FormBook C2 check-in alerts.

## Evidence

Source pcap: `2026-08-09-traffic-analysis-exercise.pcap.zip` (password on the site's "about" page; not committed to this repo). Screenshots are in the `screenshots/` folder.

**prepared By:** Stephen Wambui | Cybersecurity and Digital Forensics, MMUST

