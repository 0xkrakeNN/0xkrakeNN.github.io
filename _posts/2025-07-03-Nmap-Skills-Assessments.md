---
title: Nmap Skills Assessments
date: 2025-07-04 15:00:00 +/-0100
categories: [CPTS Modules Skills Assessments]
tags: [CPTS,Skills Assessments,HackTheBox,Nmap]
image: /assets/img/Modules-Skills-Assessments/Nmap/Nmap.png
description: 
    In this post, I share my experience completing the Nmap skills assessment module. From host discovery to port scanning and version detection, I walk through practical use cases and key takeaways.
---


## Firewall and IDS/IPS Evasion - Easy Lab

A company has hired us to assess the effectiveness of their IT security, specifically focusing on their `IDS` and `IPS` systems. After each successful test, the client plans to strengthen these defenses, although the criteria for their changes are unknown to us. Our task is to gather specific information based on each test scenario. We’re only given access to a machine protected by IDS/IPS systems for testing purposes.

we'll begin by scanning for open ports:

```bash
krakenn@Phoenix:~$ sudo nmap -Pn -n 10.129.68.135

Not shown: 869 closed tcp ports (reset), 128 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
10001/tcp open  scp-config

Nmap done: 1 IP address (1 host up) scanned in 2.31 seconds
```

- As we can see, ports `22 (SSH)` and `80 (HTTP)` are open.  
- We can identify OS in use using the service scan flag `-sV` on port `22`.

```bash
krakenn@Phoenix:~$ sudo nmap -Pn -n -p 22 -sV 10.129.68.135\
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-26 16:41 +01
Nmap scan report for 10.129.68.135
Host is up (0.052s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 <FLAG> 4ubuntu0.7 (<FLAG> Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds
```

- OS in use is `<FLAG>`.

## Firewall and IDS/IPS Evasion - Medium Lab

The first step in this scenario is to perform a scan on TCP port 53 to check if it's open and how the IDS/IPS reacts to the attempt.

```bash
┌──(krakenn㉿Phoenix)-[~/0xkrakeNN.github.io]
└─$  sudo nmap -Pn -n -p 53 10.129.2.48                                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-04 17:04 +01
Nmap scan report for 10.129.2.48
Host is up.

PORT   STATE    SERVICE
53/tcp filtered domain

Nmap done: 1 IP address (1 host up) scanned in 2.13 seconds
```

- Port 53 is marked as `filtered` which means that Nmap cannot identify if the port is open or closed because either no response is returned from the target for the port or we get an error code from the target. → **IPS is in use**.  
Usually DNS operates on UDP/53 , so let's first scan its state.  
Let's scan UDP port 53:

```bash
┌──(krakenn㉿Phoenix)-[~/0xkrakeNN.github.io]
└─$  sudo nmap -Pn -n -p 53 10.129.2.48  
PORT   STATE SERVICE VERSION
53/udp open  domain  (unknown banner: HTB{GoTt...})
| dns-nsid: 
|_  bind.version: HTB{GoTt...}
| fingerprint-strings: 
|   DNS-SD: 
|     _services
|     _dns-sd
|     _udp
|     local
|     ROOT-SERVERS
|   DNSVersionBindReq: 
|     version
|     bind
|     HTB{GoTt...}
|   NBTStat: 
|     CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
|_    ROOT-SERVERS
```

- DNS Version: `HTB{GoTt...}`

## Firewall and IDS/IPS Evasion - Hard Lab

- Now our client wants to know if it is possible to find out the version of the running services. Identify the version of service our client was talking about and submit the flag as the answer. 

We need to identify the version of a specific port (we don't know which port).  
So let's with scaning all ports using `-p-` flag  
We need to use a Firewall an IDS/IPS evasion technique. We'll use the `--source-port` flag  

```bash
┌──(krakenn㉿Phoenix)-[~/0xkrakeNN.github.io]
└─$ sudo nmap -Pn -n -T4 -p- -source-port 53 10.129.68.55 
Host is up (0.053s latency).                                                                                                                                                                                                               
Not shown: 64562 closed tcp ports (reset), 970 filtered tcp ports (no-response)                                                                                                                                                            
PORT      STATE SERVICE                                                                                                                                                                                                                    
22/tcp    open  ssh                                                                                                                                                                                                                        
80/tcp    open  http                                                                                                                                                                                                                       
50000/tcp open  ibm-db2  
```

- Open ports: `80/tcp HTTP`, `22/TCP SSH` and `50000/TCP ibm-db2`
now let's try to identify the version of the open ports:

```bash
┌──(krakenn㉿Phoenix)-[~/0xkrakeNN.github.io]
└─$ sudo nmap -Pn -n -T4 -source-port 53 -p 50000,80,22 -sV -A 10.129.68.55  
Host is up (0.056s latency).

PORT      STATE    SERVICE VERSION
22/tcp    filtered ssh
80/tcp    filtered http
50000/tcp filtered ibm-db2
Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   86.58 ms 10.10.14.1
2   86.64 ms 10.129.68.55
```

No usefull iformation.  
Let's try to use nc to grab the banner.   
We'll be using the flag -p to change the source port since other ports might be blocked.  

```bash
┌──(krakenn㉿Phoenix)-[~/0xkrakeNN.github.io]
└─$ nc -p 53 10.129.68.55 50000
220 HTB{kjnsd...}
```

-flag → `HTB{kjnsd....}`