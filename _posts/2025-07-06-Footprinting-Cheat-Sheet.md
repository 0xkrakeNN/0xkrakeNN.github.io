---
title: Network Enumeration with Nmap - Cheat Sheet
date: 2025-07-06 19:00:00 +/-0100
categories: [CPTS Modules Cheat Sheets]
tags: [CPTS,HackTheBox, Cheat Sheet]
image: /assets/img/CPTS-Cheat-Sheets/Footprinting/Footprinting.png
description: 
    Putting together a handy cheat sheet from the Footprinting module
---

## Domain Information

| Command | Description |
|--------|------------|
| `curl -s https://crt.sh/\?q\=<Target-Domain>\&output\=json | jq .` | Certificate transparency (Includes subdomains that use the same certificate) |
| `for i in $(cat ip-addresses.txt);do shodan host $i;done` | Scan an IP list using Shodan. |
| `dig any <Target_Domain>` | DNS Records |

## FTP

| Command | Description |
|--------|------------|
| `ftp <IP>` | Connect to FTP |
| `openssl s_client -connect <IP>:<Port> -starttls ftp` | Connect to FTP using an encrypted connection |
|ftp> `status`| Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on. |
| ftp> `get <File_Name>` | Download a file from the server to the client |
|ftp> `put <File_Name>` | Upload a file From the client to the FTP server |
| ftp> `DELE` <FIle_Name> | Delete a file |
| ftp> `MKD` <Directory_Name> | Create a Directory |
| ftp> `RMD` <Directory_Name> | Remove a Directory |
| ftp> `wget -m --no-passive ftp://<Username>:<Password>@<IP>` | Download all available files |

## SMB

| Command | Description |
|--------|------------|
| `smbclient //<IP/FQDM>/<Share>` | Connect to a specific share |
| `smbclient -N -L //<IP/FQDN>` | List shares using Anonymous Login |
|smb> `get <File_Name>` | Download a File |
| `impacket-samrdump <IP>` | Brute forcing User RIDs → Enumerate Users |
| `smbmap -H <IP>` | Enumerate Shares |
| `crackmapexec smb <IP> --shares -u '' -p '' ` | Enumerate Shares using null session authentication|
| `enum4linux-ng.py <IP/FQDN> -A` | SMB enumeration using enum4linux |
| `rpcclient -U '' <IP/FQDN>`| Interacting with the target using RPC |

### RPCCLEINT Functions to execute

| Command | Description |
|--------|------------|
| `srvinfo` | server information |
| `enumdomains` | enumerate all domains that are deployed on the network  |
| `querydominfo` | Provides domain, server, and user information of deployed domains |
| `netsharegetinfo <share>` | Provide information about specific share |
| `enumdomusers` | Enumerate all domain users | 
| `queryuser <RID>` | Provide information about specific user |
| `querygroup <RID>` | Provide information about a specific group |

