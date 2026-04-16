# Invoke-DBWebSiteFingerprint

`Invoke-DBWebSiteFingerprint` is a PowerShell function for fingerprinting web infrastructure using both **TLS (JARM)** and **non-TLS techniques**.

It is designed for threat hunting, DFIR, and infrastructure clustering — especially useful when dealing with malware hosting or attacker-controlled servers that may not use TLS.

Initially based on https://github.com/salesforce/jarm

The HTTP-based fingerprinting is research based, I'm not sure it will work but feel free to comment on that


---

## Features

- Native **JARM TLS fingerprinting**
- **HTTP-based fingerprinting** for non-TLS servers
- Extraction of URLs from HTML and scripts
- Detection of directory listings and hosted files
- Optional **port probing and banner grabbing**
- Basic **WHOIS / provider enrichment**
- Composite fingerprint for clustering related hosts

---

## Usage

```powershell
Invoke-DBWebSiteFingerprint -Url "https://example.com"

Invoke-DBWebSiteFingerprint -Url "http://example.com" -Ports 22,80,443

Invoke-DBWebSiteFingerprint -Url "https://example.com" -JarmOnly