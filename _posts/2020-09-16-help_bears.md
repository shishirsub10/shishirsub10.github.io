---
title: "Help Bears TryHackMe Write Up"
last_modified_at: 2020-09-16T14:40:02-05:00
categories:
  - thm
author_profile: false
tags:
  - Steganography
  - Crypto
---

Link: [https://tryhackme.com/room/helpbears](https://tryhackme.com/room/helpbears)

Introduction
------------

![i](https://miro.medium.com/max/700/1*rx1agjUj2iTBEk3qTge-KA.png)

The introduction says that the BEARS need our help to solve a few challenges.

FLAG 1
------

Download the file & get going…

And the downloaded file contains:

```js
É=-~-~[],ó=-~É,Ë=É<<É,þ=Ë+~[];Ì=(ó-ó)[Û=(''+{})[É+ó]+(''+{})[ó-É]+([].ó+'')[ó-É]+(!!''+'')[ó]+({}+'')[ó+ó]+(!''+'')[ó-É]+(!''+'')[É]+(''+{})[É+ó]+({}+'')[ó+ó]+(''+{})[ó-É]+(!''+'')[ó-É]][Û];Ì(Ì((!''+'')[ó-É]+(!''+'')[ó]+(!''+'')[ó-ó]+(!''+'')[É]+((!''+''))[ó-É]+([].$+'')[ó-É]+'\''+''+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(þ)+(É+ó)+'\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó-É)+(É+ó)+(É+ó)+'\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(É+ó)+(ó-ó)+'\\'+(É+É)+(þ)+'\\'+(ó-É)+(ó-ó)+(É+ó)+'\\'+(ó-É)+(É+ó)+(ó+ó)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(þ)+(É)+'\\'+(É+É)+(ó-ó)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(É+É)+(ó-ó)+'\\'+(ó-É)+(É+ó)+(É+ó)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(É+É)+(ó-ó)+'\\'+(ó-É)+(É+É)+(É+É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(É+É)+(ó-ó)+'\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(ó+ó)+(ó)+'\\'+(ó-É)+(ó+ó)+(ó)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(É+É)+(þ)+'\\'+(É+ó)+(ó-É)+'\\'+(þ)+(ó)+'\\'+(ó-É)+(É+ó)+(ó-É)+'\\'+(ó-É)+(É+É)+(ó+ó)+'\\'+(É+ó)+(ó-ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(þ)+(É+ó)+'\\'+(þ)+(É+ó)+'\\'+(É+É)+(þ)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó+ó)+(ó-É)+'\\'+(ó+ó)+(É)+'\\'+(ó+ó)+(ó)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(É+É)+(þ)+'\\'+(É+ó)+(ó-É)+'\\'+(ó-É)+(þ)+(ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(É+ó)+(ó-ó)+'\\'+(É+É)+(þ)+'\\'+(ó-É)+(É+É)+(É)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(ó+ó)+(ó+ó)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(É+É)+(þ)+'\\'+(É+ó)+(ó-É)+'\\'+(þ)+(ó)+'\\'+(ó-É)+(þ)+(É+ó)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(ó+ó)+(ó)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(þ)+(ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(É+ó)+(ó-ó)+'\\'+(É+É)+(þ)+'\\'+(ó-É)+(É+É)+(ó+ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(É+ó)+(ó-É)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(É+ó)+(ó+ó)+'\\'+(É+ó)+(ó+ó)+'\\'+(É+ó)+(ó+ó)+'\\'+(É+É)+(þ)+'\\'+(É+ó)+(ó-É)+'\\'+(þ)+(ó)+'\\'+(ó-É)+(þ)+(É+ó)+'\'')())()
```

It looks like Obfuscated JS.

While searching around, i came across [this article.](https://stackoverflow.com/questions/20884577/how-to-deobfuscate-javascript)

```js 
É=-~-~[],ó=-~É,Ë=É<<É,þ=Ë+~[];Ì=(ó-ó)[Û=(''+{})[É+ó]+(''+{})[ó-É]+([].ó+'')[ó-É]+(!!''+'')[ó]+({}+'')[ó+ó]+(!''+'')[ó-É]+(!''+'')[É]+(''+{})[É+ó]+({}+'')[ó+ó]+(''+{})[ó-É]+(!''+'')[ó-É]][Û];Ì(Ì((!''+'')[ó-É]+(!''+'')[ó]+(!''+'')[ó-ó]+(!''+'')[É]+((!''+''))[ó-É]+([].$+'')[ó-É]+'\''+''+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(þ)+(É+ó)+'\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó-É)+(É+ó)+(É+ó)+'\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(É+ó)+(ó-ó)+'\\'+(É+É)+(þ)+'\\'+(ó-É)+(ó-ó)+(É+ó)+'\\'+(ó-É)+(É+ó)+(ó+ó)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(þ)+(É)+'\\'+(É+É)+(ó-ó)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(É+É)+(ó-ó)+'\\'+(ó-É)+(É+ó)+(É+ó)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(É+É)+(ó-ó)+'\\'+(ó-É)+(É+É)+(É+É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(É+É)+(ó-ó)+'\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(ó+ó)+(ó)+'\\'+(ó-É)+(ó+ó)+(ó)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(É+É)+(þ)+'\\'+(É+ó)+(ó-É)+'\\'+(þ)+(ó)+'\\'+(ó-É)+(É+ó)+(ó-É)+'\\'+(ó-É)+(É+É)+(ó+ó)+'\\'+(É+ó)+(ó-ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(þ)+(É+ó)+'\\'+(þ)+(É+ó)+'\\'+(É+É)+(þ)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó+ó)+(ó-É)+'\\'+(ó+ó)+(É)+'\\'+(ó+ó)+(ó)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(É+É)+(þ)+'\\'+(É+ó)+(ó-É)+'\\'+(ó-É)+(þ)+(ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(É+ó)+(ó-ó)+'\\'+(É+É)+(þ)+'\\'+(ó-É)+(É+É)+(É)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(ó+ó)+(ó+ó)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(É+É)+(þ)+'\\'+(É+ó)+(ó-É)+'\\'+(þ)+(ó)+'\\'+(ó-É)+(þ)+(É+ó)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(ó+ó)+(ó)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(þ)+(ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(É+ó)+(ó-ó)+'\\'+(É+É)+(þ)+'\\'+(ó-É)+(É+É)+(ó+ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(É+ó)+(ó-É)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(É+ó)+(ó+ó)+'\\'+(É+ó)+(ó+ó)+'\\'+(É+ó)+(ó+ó)+'\\'+(É+É)+(þ)+'\\'+(É+ó)+(ó-É)+'\\'+(þ)+(ó)+'\\'+(ó-É)+(þ)+(É+ó)+'\'')()).toString()
```

And just deleting the last ‘()’ and replacing with toString() gives us.

![i](https://miro.medium.com/max/698/1*A968Wzq_GyRuTOXS9nEznw.png)

And we got the first flag.

FLAG 2
------

Download the file & find the password.

File Contents:

```
var pass = unescape("unescape%28%22String.fromCharCode%2528104%252C68%252C117%252C102%252C106%252C100%252C107%252C105%252C49%252C53%252C54%2529%22%29");
```

Double URL decoding the contents:

```
varpass=unescape("unescape("String.fromCharCode("104,68,117,102,106,100,107,105,49,53,54)")");
```

And Converting the decimal value “104,68,117,102,106,100,107,105,49,53,54” to ascii, we get next flag.

![i](https://miro.medium.com/max/637/1*wGxqFEly5AQyRqK4m_Wr6Q.png)

FLAG 3
------

There’s a flag hidden somewhere. Can you find it?

Looking at the files that i have downloaded, i didn't find anything that might be hidden. As the challenge has a stegno tag, I noticed a image on the Introduction section.

So I downloaded the image using wget.

```
wget [https://i.ibb.co/WD6ftr9/bear.jpg](https://i.ibb.co/WD6ftr9/bear.jpg)
```

Using exiftool on the image, i didnot find anything interesting.

```console 
File Name                       : bear.jpg  
Directory                       : .  
File Size                       : 26 kB  
File Modification Date/Time     : 2020:06:22 17:54:51+05:45  
File Access Date/Time           : 2020:08:12 20:52:28+05:45  
File Inode Change Date/Time     : 2020:08:12 20:52:09+05:45  
File Permissions                : rw-r--r--  
File Type                       : JPEG  
File Type Extension             : jpg  
MIME Type                       : image/jpeg  
JFIF Version                    : 1.01  
Resolution Unit                 : inches  
X Resolution                    : 120  
Y Resolution                    : 120  
Image Width                     : 450  
Image Height                    : 300  
Encoding Process                : Baseline DCT, Huffman coding  
Bits Per Sample                 : 8  
Color Components                : 3  
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)  
Image Size                      : 450x300  
Megapixels                      : 0.135
```

I ran strings against the image, but i didn't find anything interesting there too.

```console 
strings bear.jpg
```

As it was a jpeg image, i tried extracting the hidden data, if there was any, using steghide with blank password.

```console 
$ steghide extract -sf bear.jpg   
Enter passphrase:   
steghide: could not extract any data with that passphrase!
```

So I decided to bruteforce the password using stegcrack and with rockyou.txt wordlist.

```console 
$ stegcracker bear.jpg /usr/share/wordlists/rockyou.txt  
StegCracker 2.0.9 - ([https://github.com/Paradoxis/StegCracker](https://github.com/Paradoxis/StegCracker))  
Copyright (c) 2020 - Luke Paris (Paradoxis)Counting lines in wordlist..  
Attacking file 'bear.jpg' with wordlist '/usr/share/wordlists/rockyou.txt'..  
Successfully cracked file with password: pandas  
Tried 2820 passwords  
Your file has been written to: bear.jpg.out  
pandas
```

And we successfully cracked the password. And i manually extracted the file using steghide as stegcracker renamed the actual file to bear.jpg.out.

```console 
$:~ steghide extract -sf bear.jpg  
Enter passphrase:   
wrote extracted data to "challenge.txt".
```

Looking at file using cat

```console
$:~ cat challenge.txt   
Grizzly‌‌‌‌‍!‌‌‌‌‌
```

Looking the file challenge.txt in Vim

```
<200c><200c><200c><200c><200d><200c><200d><202c>Grizzly<200c><200c><200c><200c><200d><202c><feff><200c><200c><200c><200c><200c><200d><202c><200c><200d><200c><200c><200c><200c><200d><202c><200d><feff><200c><200c><200c><200c><200c><feff><202c><202c><200c><200c><200c><200c><200c><202c><200c><200c><200c><200c><200c><200c><200c><202c><202c><202c><200c><200c><200c><200c><200c><feff><202c><feff><200c><200c><200c><200c><200d><feff><feff><200d><200c><200c><200c><200c><200c><feff><202c><200d><200c><200c><200c><200c><200c><feff><200d><200c><200c><200c><200c><200c><200c><feff><feff><feff><200c><200c><200c><200c><200d><feff><feff><200d><200c><200c><200c><200c><200c><feff><200d><feff><200c><200c><200c><200c><200c><202c><202c><feff><200c><200c><200c><200c><200d><200c><202c><feff><200c><200c><200c><200c><200d><feff><200c><200c><200c><200c><200c><200c><200d><200c><202c><200c><200c><200c><200c><200c><200c><feff><200c><feff>!<200c><200c><200c><200c><200c><feff><feff><202c><200c><200c><200c><200c><200d><feff><200d><200d><200c><200c><200c><200c><200c><feff><200d><feff><200c><200c><200c><200c><200c><feff><200d><200c><200c><200c><200c><200c><200d><feff><200d><202c><200c><200c><200c><200c><200d><feff><200d><200c><200c><200c><200c><200c><200c><feff><feff><200c><200c><200c><200c><200c><200d><feff><202c><200d><200c><200c><200c><200c><200d><feff><200d><200d><200c><200c><200c><200c><200d><202c><202c><200c><200c><200c><200c><200c><200d><200d><feff><feff><200c><200c><200c><200c><200d><feff><feff><200d><200c><200c><200c><200c><200d><feff><200d><202c><200c><200c><200c><200c><200c><202c><200d><feff><200c><200c><200c><200c><200c><feff><200d><feff><200c><200c><200c><200c><200d><feff><feff><200c><200c><200c><200c><200c><200d><feff><200d><200d><200c><200c><200c><200c><200d><feff><feff><200d><200c><200c><200c><200c><200d><feff><200c><feff><200c><200c><200c><200c><200c><202c><200d><202c><200c><200c><200c><200c><200d><feff><200c><200c><200c><200c><200c><200c><200d><202c><feff><200c><200c><200c><200c><200c><200d><202c><feff><200c>
```

I was familiar with the data hiding using unicode spaces and normal spaces. But this was new to me. So I searched around and found [this website](https://330k.github.io/misc_tools/unicode_steganography.html) explaining the use of zero width character for stegnography and also has a decoder.

Decoder on the Website

![i](https://miro.medium.com/max/1000/1*VDkd_11Z9NjGt2PCsnqPPQ.png)

But i was having problem copying the text. So i used a tool called xclip.

Xclip can be install from apt.

```console 
$ apt install xclip
```

Using xclip, I copied the content of the file challenge.txt and pasted on the site .

```console 
$ cat challenge.txt | xclip -selection clipboard
```

After it decoded the content, I downloaded a file.

![i](https://miro.medium.com/max/700/1*520Kdq-lc2SBLyb-mLpyAw.png)

Looking at the contents of the downloaded file

```
^@F^@l^@a^@g^@:^@ ^@*^@;^@}^@9^@4^@?^@}^@7^@+^@K^@p^@H^@3^@>^@u^@7^@4^@v^@t^@<^@y^@u^@h^@_^@}^@v^@'^@7^@|^@u^@}^@s^@&^@p^@l^@l
```

Clearing the gibberish text

```
Flag: *;}94?}7+KpH3>u74vt<yuh_}v'7|u}s&pll
```

I was having strong doubts that it doesn't look like a flag, but I couldn't resist and submitted the flag. And the flag was incorrect.

It looked like a cipher, and just by inspection I thought it was rot47 cipher. So I went to [this site](https://www.dcode.fr/rot-47-cipher) to decode the cipher.

![i](https://miro.medium.com/max/700/1*rbGElIz9B5mnuiSrJjAnNQ.png)

And now the output looked familiar. It was a base64 encoded string. So i decoded the string and finally got the final flag.

![i](https://miro.medium.com/max/606/1*ATgiSSjoVZZU1GDBfl0FWQ.png)

Thank you for reading the write up. Reply if you have any suggestions regarding the write up. Hope you have enjoyed reading as much as i have enjoyed writing it.

This article was first published on medium and regenerated using npm module medium-to-markdown.  
You can read my article on [medium](https://medium.com/@shishirsub10/tryhackme-help-bears-80961b2b551b)
