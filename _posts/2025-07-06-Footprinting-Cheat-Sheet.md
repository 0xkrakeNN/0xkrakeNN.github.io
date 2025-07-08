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

**Source:** [RPCCLIENT](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html)

## NFS

| Command | Description |
|--------|------------|
| `showmount -e <IP/FQDN> ` | Show available Shares |
| `sudo mount -t nfs <IP/FQDN>:/<FileShare> ./target-nfs -o nolock` | Mount the specific NFS share |
| `umount ./target-NFS` | Unmount The specific NFS Share |

## DNS

| Command | Description |
|--------|------------|
| `dig ns <Domain.tld> @<Nameserver>` | NS Query to the specified nameserver |
| `dig any <Domain.tld> @<Nameserver>` | Any Query to the specified nameserver |
| `dig CH TXT version.bind @<Nameserver>` | Version Query to the specified nameserver |
| `dig axfr @<Nameserver>` | AXFR Query (Zone transfer) from a specified nameserver |
| `dnsenum --dnsserver <Nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <Domain.tld>` | Subdomain brute forcing |

> - An `AXFR` request retrieves a complete copy of a zone's DNS records from an authoritative server.  
- The `CHAOS` class (shortened as CH) is one of the original DNS classes, introduced alongside the more common IN (Internet) class. While the IN class is used for almost all modern DNS lookups (A, AAAA, CNAME, etc.), the CHAOS class serves a special diagnostic/debugging purpose (`version.bind`, `hostname.bind`, `authors.bind`).
{: .prompt-info }

## SMTP

| Command | Description |
|--------|------------|
| `telnet <IP/FQDM> <Port>` | Connect to the SMTP Server 
|smtp> `HELO <Hostname>` | Login the Computer Name. → Start the session |
|smtp> `AUTH PLAIN <\0USERNAME\0PASWORD>`| Authenticate the client. The creds should be encrypted in **base64** |
| smtp> `MAIL FROM: <krakenn@gmail.com>` | Sender Mail |
| smtp>  `RECPT TO: <victim@gmail.com> NOTIFY=success,failure`| Recepient Mail + notification on success or failure (We can remove it) |
| smtp> `DATA` | Start Email content transmission |
| smtp> `RST` | The client cancels the ongoing transmission while maintaining the connection with the server. |
| smtp> `VRFY krakenn` | Checks if a mailbox exists. (Can be used for users enumeration) |
| mstp> `NOOP` | Sends a harmless command to the server to keep the session alive. |
| smtp> `QUIT` | Close the connection. |

### SMTP Command example

```bash
┌──(krakenn㉿Phoenix)-[~]
└─$ telnet 10.129.21.32 25
Trying 10.129.21.32...
Connected to 10.129.21.32.
Escape character is '^]'.
HELO phoenix.local 
220 InFreight ESMTP v2.11
250 mail1
MAIL FROM: <krakenn@gmail.com>
250 2.1.0 Ok
RCPT TO: <Victim@gmail.com> NOTIFY=success,failure
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
FROM: <spoofedmail@gmail.com>
TO: <victim@gmail.com>
Subject: Password reset      
Date: Mon, 07 July 2025 16:48:00 +0100
Hello, you need to change your password
Click here to change it.
.
250 2.0.0 Ok: queued as 344B4125F
QUIT
221 2.0.0 Bye
Connection closed by foreign host.
```

You can check status codes [HERE](https://serversmtp.com/smtp-error/)

## IMAP/POP3

### IMAP

| Command | Description |
|--------|------------|
| `curl -k 'imaps://<IP/FQDN>' --user <Username>:<Password>` | Login to THE IMAPS service using cURL |
| `openssl s_client -connect <FQDN/IP>:imaps` | Connect to IMAPS service over SSL |
| IMAP> `A1 LOGIN <Username> <Password>` | Login using creds | 
| IMAP> `A1 LIST "" *` | List all directories |
| IMAP> `A1 CREATE "<Mailbox_Name>"` | Create a Mailbox |
| IMAP> `A1 DELETE "<Mailbox_Name>"` | Delete a Mailbox |
| IMAP> `A1 RENAME "<Mailbox_Name>" "<New_Mailbox_Name>"` | Rename a mailbox or a folder |
| IMAP> `A1 LSUB "" *`  | List mailboxes that the user is subscribed to |
| IMAP> `A1 SELECT <Mailbox>` | Select a mailbox to access the messages it contains |
| IMAP> `A1 UNSELECT <Mailbox>` | Exit the mailbox |
| IMAP> `A1 FETCH <ID> all` | Retrieve message data from the mailbox |
| IMAP> `A1 LOGOUT `| Closes the connection with the IMAP server |

More CMDs [HERE](https://www.atmail.com/blog/imap-commands/) 

### POP3

| Command | Description |
|--------|------------|
| `openssl s_client -connect <FQDN/IP>:pop3s` | Connect to IMAPS service over SSL |
| POP3>  `USER <Username>` | Identify the user using the username |
| POP3> `PASS <Password>` | AUthenticate then user using creds provided |
| POP3> `STAT` | Request the total count of saved emails on the server. |
| POP3> `LIST` | Request from the server the number and size of all emails. |
| POP3> `RETR <ID>` | Retrieve the requested email by ID |
| POP3> `QUIT` | Close the connection |
