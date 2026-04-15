<div align="center">

# netguard

![C++](https://img.shields.io/badge/C++-Network_Analysis-blue?style=flat&logo=c%2B%2B)
![License](https://img.shields.io/badge/License-MIT-green)
![Type](https://img.shields.io/badge/Type-IDS-orange)

<p>
  <strong>A lightweight, signature-based Intrusion Detection System (IDS) for Linux.</strong>
</p>

[Report Bug](https://github.com/egetones/netguard/issues) · [Request Feature](https://github.com/egetones/netguard/issues)

</div>

---

## Description

**NetGuard** is a Proof-of-Concept (PoC) Network Intrusion Detection System written in C++. 
It listens to live TCP traffic using Raw Sockets and inspects the payload of each packet against a database of known attack signatures.

Unlike a simple sniffer (which only displays data), NetGuard **analyzes** the data. If it detects malicious patterns—such as SQL Injection queries, XSS payloads, or suspicious system commands—it triggers a real-time alert with details about the source and destination.

### Key Features

  **Real-Time Deep Packet Inspection (DPI):** Analyzes packet payloads on the fly.
  **Signature Based Detection:** Matches patterns against a custom list of threats (SQLi, XSS, RCE).
  **Low Level Networking:** Built directly on top of Linux Socket API without external libraries like libpcap.

---

## Usage

**⚠️ Requirement:** Needs `root` privileges to open Raw Sockets.

### 1. Compile
```bash
make
```

### 2. Run
```bash
sudo ./netguard
```

### 3. Simulate an Attack (Test)
While NetGuard is running in one terminal, open another terminal and simulate a malicious request using `curl`:

**Simulate XSS:**
```bash
curl "[http://google.com?q=](http://google.com?q=)<script>alert(1)</script>"
```

**Simulate SQL Injection:**
```bash
curl "[http://testphp.vulnweb.com/artists.php?artist=1](http://testphp.vulnweb.com/artists.php?artist=1) UNION SELECT 1,2,3"
```

**NetGuard Output:**
```text
[!!!] SALDIRI TESPİT EDİLDİ [!!!]
 [*] Tehdit Türü: XSS Attack Attempt
 [*] Kaynak: 192.168.1.35 -> Hedef: 142.250.187.142
 [*] İçerik Parçası: <script>
```

---

## ⚠️ Disclaimer

This tool is for **educational purposes only**. It is a simplified demonstration of how IDS technologies function. It is not intended to replace production-grade systems like Snort or Suricata.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
