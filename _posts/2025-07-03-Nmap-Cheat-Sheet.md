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

**Host Discover**

| Command | Description|
|--------|------------|
| ```bash -sn ``` | Disable port scanning. Host discovery only. |
| ```bash -PE``` | Performs the ping scan by using ICMP Echo Requests against the target |
| ```bash nmap -sn 10.129.2.12``` | Scan Single IP |
| ```bash nmap -sn 10.129.2.0/24 ``` | Scan Network range |
| ```bash nmap -sn -iL hosts.lst ``` | Scan IP List |
| ```bash nmap -sn 10.129.2.12 10.129.2.13 10.129.2.17``` | Scnan Multiple IPs  |
| ```bash nmap -sn 10.129.2.12-18``` | Scan Multiple IPs