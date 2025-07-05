---
title: Network Enumeration with Nmap - Cheat Sheet
date: 2025-07-03 19:19:00 +/-0100
categories: [CPTS Modules Cheat Sheets]
tags: [CPTS,HackTheBox, Cheat Sheet]
image: /assets/img/Modules-Skills-Assessments/Nmap/Nmap.png
description: 
    Putting together a handy cheat sheet from the Nmap module
---


**SYNTAX**
```bash
nmap <scan types> <options> <target>
```

## Host Discover

| Command | Description|
|--------|------------|
| `-sn ` | Disable port scanning. Host discovery only. |
| `-PE` | Performs the ping scan by using ICMP Echo Requests against the target |
| `nmap -sn 10.129.2.12` | Scan Single IP |
| `nmap -sn 10.129.2.0/24` | Scan Network range |
| `nmap -sn -iL hosts.lst` | Scan IP List |
| `nmap -sn 10.129.2.12 10.129.2.13 10.129.2.17` | Scnan Multiple IPs  |
| `nmap -sn 10.129.2.12-18` | Scan Multiple IPs

## Port Scanning

| Command | Description|
|--------|------------|
| `-sS` | Syn Scan |
| `-sT` | TCP Scan |
| `-sU` | UDP Scan |
| `--top-ports=10` | Scans the specified top ports that have been defined as most frequent. |
| `-F` | Fast Scan. Scans top 100 Ports|
| `-Pn` | Treat all hosts as online -- skip host discovery|
| `-p 80` | Only scan Port 80 |
| `-p 80,8080` | scan Ports 80 and 8080 |
| `-p 80-90` | Scan port range |
| `-p-` | Scan all ports |

## Saving The Results

| Command | Description|
|--------|------------|
| `-oN` | Normal output with the **.nmap** file extension |
| `-oG` | Grepable output with the **.gnmap** file extension |
| `-oX` | XML output with the **.xml** file extension |
| `-oA Target` | Saves the results in all formats, starting the name of each file with **Target**.|

## Service and OS Enumeration

| Command | Description|
|--------|------------|
| `-O` | OS Detection |
| `-sV` | Service version enumeration |
| `-A` | Agressive Scanning. Enables OS detection (**-O**), version detection (**-sV**), script scanning (**-sC**), and traceroute (**--tracerout**)  |

## Nmap Scripting Engine (NSE)

| Command | Description|
|--------|------------|
| `-sC` | default NSE scripts. Equivalent to --script=default |
| `--script <category>` | Use specific Scripy category |
| `--script <scripy_Name>,<script_Name>`| Use defined scripts |

### Script Categories

| Script Category | Description |
|--------|------------|
| `auth` | Determination of authentication credentials. |
| `broadcast` | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| `brute` | Executes scripts that try to log in to the respective service by brute-forcing with credentials. |
| `default` | Default scripts executed by using the -sC option. |
| `discovery` | Evaluation of accessible services. |
| `dos` | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services. |
| `exploit` | This category of scripts tries to exploit known vulnerabilities for the scanned port. |
| `external` | Scripts that use external services for further processing. |
| `fuzzer` | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time. |
| `intrusive` | Intrusive scripts that could negatively affect the target system. |
| `malware` | Checks if some malware infects the target system. |
| `safe` | Defensive scripts that do not perform intrusive and destructive access. |
| `version` | Extension for service detection. |
| `vuln` | Identification of specific vulnerabilities. |

## Performance

| Command | Description|
|--------|------------|
|  |