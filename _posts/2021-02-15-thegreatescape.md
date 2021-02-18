---
title: "The Great Escape TryHackMe Writeup"
last_modified_at: 2021-02-15T11:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - Linux
  - SSRF
  - web
  - code injection
  - docker
  - nmap
  - custom wordlist
  - bruteforcing
  - port knocking
  - ctf
  - thegreatescape
---

<img alt="bookstore" src="/assets/images/thm/thegreatescape/thegreatescape.png" width="200px" height="50px">

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>

[The Great Escape](https://tryhackme.com/room/thegreatescape) is a medium rated Linux based room on tryhackme by [hydragyrum](https://tryhackme.com/p/hydragyrum). SSRF along with code injection was used to get a root shell on a docker container. Using Port knocking sequence, TCP port for Docker container was opened which was used to get a root shell on the box. 

# Port Scan

## Full Port Scan
```console
reddevil@ubuntu:~/Documents/tryhackme/thegreateescape$ nmap -p- -min-rate 10000 -v -oN nmap/all-ports 10.10.238.100
Nmap scan report for 10.10.238.100
Host is up (0.32s latency).
Not shown: 65366 closed ports, 167 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
# Nmap done at Mon Feb 15 01:21:34 2021 -- 1 IP address (1 host up) scanned in 31.43 seconds
```
Only two ports are open. SSH is running on port 22 and HTTP service is running on port 80.


## Detail Scan
```console
reddevil@ubuntu:~/Documents/tryhackme/thegreateescape$ nmap -p22,80 -sC -sV -oN nmap/detail 10.10.207.95
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-15 21:16 +0545
Nmap scan report for 10.10.207.95
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh?
| fingerprint-strings: 
|   GenericLines: 
|_    im4+ ^1a}wVQbdyQ/{VY!;
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp open  http    nginx 1.19.6
| http-robots.txt: 3 disallowed entries 
|_/api/ /exif-util /*.bak.txt$
|_http-server-header: nginx/1.19.6
|_http-title: docker-escape-nuxt
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port22-TCP:V=7.80%I=7%D=2/15%Time=602A93D9%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,18,"im4\+\x20\^1a}wVQbdyQ/{VY!;\r\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 195.25 seconds
```


Let us start the enumeration with HTTP service on port 80.

# HTTP service on Port 80
![1](/assets/images/thm/thegreatescape/1.png)

Clicking on /courses, /admin redirected me to /login and the signup seems to be disabled.

![2](/assets/images/thm/thegreatescape/2.png)

Normally my next step would be directory and files bruteforcing, but this webapp has a firewall in place which has a rate limiting.

## Entries on robots.txt
```console
reddevil@ubuntu:~/Documents/tryhackme/thegreateescape$ curl 10.10.207.95/robots.txt
User-agent: *
Allow: /
Disallow: /api/
# Disallow: /exif-util
Disallow: /*.bak.txt$
```
We can see that there are three entries on robots.txt

## Checking /exif-util
![3](/assets/images/thm/thegreatescape/3.png)
Looking at the title of the webpage `Exif Utlis`, it looks like we can upload a file and this app will display the metadata of that file. Also the file can be included by an URL.

### Uploading a test image
![4](/assets/images/thm/thegreatescape/4.png)
I uploaded a PNG image and the app gave the information about the image. We can see that the app is making a request to **/api/exif** and the file name of the uploaded file is also changed.


### Including image via URL
I have hosted files using python server from my device.
![5](/assets/images/thm/thegreatescape/5.png)
This time we made a GET request to **/api/exif** with a parameter called **url**.

## Checking if the URL parameter is vulnerable to SSRF
From the Nmap scan,we saw that port 22 and 80 are open.
### Checking whether we get a response from port 80
![6](/assets/images/thm/thegreatescape/6.png)
I did not get any response either from port 80 or 22. As I was manually poking, I got reponse from port 8080.

### Port 8080
![7](/assets/images/thm/thegreatescape/7.png)
Since we know that our host has port 22 and 80 open, I thought that this webapp must be running inside a docker container.

### Checking for port 80 on docker's interface
![8](/assets/images/thm/thegreatescape/8.png)
And my assumption was correct. Using this we can scan the whole network for open ports. Since there was rate limiting implemented, I did not bother to go down that path.

I checked for the other protocols like `file`,`zip`,`gopher`, but all of them gave some sort of error.

### File Bruteforcing
There is a interesting entry on robots.txt. ie `*.bak.txt`. Since there is rate limiting on the webserver, instead of using the usual wordlists for bruteforcing, I manually created a small custom wordlist with the words present on the webserver.

### Content of the wordlist
```console
login
users
user
photo
image
sign-up
signup
Signup
SignUp
test
courses
username
user
admin
photos
images
exif-util
classroom
class
course
photos
```
### Using wfuzz with a single thread
![9](/assets/images/thm/thegreatescape/9.png)


## Content of exif-util.bak.txt
![10](/assets/images/thm/thegreatescape/10.png)
We get a hostname. Looks like it is a api's backup docker container used by the dev team. Since this is a backup and a developement container, it might contain unpatched vulnerabilities.

## Checking for SSRF on backup container
![11](/assets/images/thm/thegreatescape/11.png)
For the empty value of the url parameter, we get a error with curl on it which means that the value of the parameter is directly passed to the curl.

### Hypothesis
```php
<?php 
url = $_GET['url'];
system('curl ' . 'url');

?>
```
If this is the case, we can get code execution.

## Trying for command injection
![12](/assets/images/thm/thegreatescape/12.png)
And we successfully executed the command. We are root, but just on the docker container.

I tried to get a reverse shell but was unsuccessful. It looks like the all the outgoing traffic is blocked by the firewall. So, I manually started going through the container.

## On /root
![13](/assets/images/thm/thegreatescape/13.png)

### Content of dev-note.txt
![14](/assets/images/thm/thegreatescape/14.png)
I tried to login with `hydra:fluffybunnies123` using SSH, but was unsuccessful.

### Enumerating the git repo
![15](/assets/images/thm/thegreatescape/15.png)
We can see that are three commits. So, lets check those out.

### Checking the commits
![16](/assets/images/thm/thegreatescape/16.png)
We get a port knocking sequence for opening docker TCP port and a flag too.

### Performing Port Knocking Sequence
![17](/assets/images/thm/thegreatescape/17.png)

## Full Port Scan
Let's run nmap to check for any new open ports.
```console
reddevil@ubuntu:~/Documents/tryhackme/thegreateescape$ nmap -p- --min-rate 10000 -v 10.10.207.95
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-15 22:42 +0545
Nmap scan report for 10.10.207.95
Host is up (0.31s latency).
Not shown: 65528 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
2375/tcp  open     docker

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 28.72 seconds
```
And we get a new port ie **2375**.

I searched and found [this](https://www.hackingarticles.in/docker-for-pentester-abusing-docker-api/) amazing article which explains that we can abuse docker API to get a root shell on the box.

## Listing docker images
![18](/assets/images/thm/thegreatescape/18.png)

We can successfully list the docker images using the API.

## Getting a root shell
![19](/assets/images/thm/thegreatescape/19.png)

Here I have created a container from `frontend` image on an interactive mode executing `sh` binary. The root file system of the host will be mounted on the `/mnt` directory of the container and the root of the container is changed to `/mnt`.

## Reading web flag
![21](/assets/images/thm/thegreatescape/21.png)

![22](/assets/images/thm/thegreatescape/22.png)

## Reading root flag
![20](/assets/images/thm/thegreatescape/20.png)



Having trouble with the writeup and need help, do not hesitate to ping me on [twitter](https://twitter.com/shishir37768334). 
