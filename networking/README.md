# Network Forensics & Traffic Analysis Labs

This directory contains labs, exercises, and threat-hunting write-ups focused on analyzing captured network traffic, identifying malicious indicators of compromise (IoCs), and dissecting protocol anomalies.

## 🛠️ Toolstack Used
* **Wireshark / Tshark:** Protocol dissection and visual packet analysis.
* **Zeek (Bro):** High-level network security monitoring and session logging.
* **Suricata / Snort:** Signature-based Network Intrusion Detection Systems (NIDS).
* **NetworkMiner:** Network forensic analysis tool (NFAT) for artifact file carving.

---

## 📂 Directory Structure

```text
networking/
├── challenges/             # Write-ups for CTFs and external traffic analysis challenges
│   ├── malware-traffic-analysis/
│   └── cyberdefenders/
├── active-hunting/         # PCAP analyses from simulated environment infections
├── alert-tuning/           # Snort/Suricata custom signature creation and testing
└── PCAPs/                  # (Optional/Ignored) Storage for raw packet capture data
```

*Note: Large `.pcap` or `.pcapng` files should be tracked using Git LFS or excluded via `.gitignore` if they contain proprietary data.*

---

## 🔍 Lab Catalog & Core Concepts Covered

### 1. Malware Traffic Analysis
* **Objective:** Identifying command-and-control (C2) beaconing, initial access vectors (e.g., malicious downloads), and lateral movement.
* **Key Protocols:** HTTP, HTTPS (TLS Handshakes/JA3 fingerprints), DNS, SMB.

### 2. Network Intrusion Detection
* **Objective:** Writing and tuning Snort/Suricata rules to detect exploitation attempts (e.g., reverse shells, scanning activity).
* **Key Protocols:** TCP/UDP streams, ICMP payloads.

### 3. Protocol Deep Dives
* **Objective:** Carving files out of unencrypted streams and analyzing protocol misconfigurations.
* **Key Focus:** Extracting PE/ELF files from HTTP streams or examining rogue DHCP/ARP behavior.

---

## 🚀 How to Use These Labs

1. **Locate the PCAP:** Navigate to the specific lab subfolder to find the target packet capture or the external link to download it.
2. **Review the Prompts:** Open the local lab guide to view the incident response scenario and the questions to answer.
3. **Analyze & Compare:** Open the target file in Wireshark or pass it through your NIDS, then compare your findings with the provided solution write-up.

---

## 📌 Useful Filters Cheat Sheet
Keep these Wireshark display filters handy during analysis:
* `http.request or tls.handshake.type == 1` – Show all web requests and TLS client hellos.
* `dns.flags.response == 0` – Filter for DNS queries only (useful for finding lookups to malicious domains).
* `tcp.flags.syn == 1 and tcp.flags.ack == 0` – Identify potential SYN port scanning.
* `ip.addr == [Target_IP] and ip.addr == [Attacker_IP]` – Isolate traffic between two specific hosts.
 
