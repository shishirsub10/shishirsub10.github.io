
> medium-to-markdown@0.0.3 convert /home/reddevil/node_modules/medium-to-markdown
> node index.js "https://medium.com/@shishirsub10/tryhackme-help-bears-80961b2b551b"

TryHackMe | Help Bears! Write Up
================================

[![Shishir Subedi](https://miro.medium.com/fit/c/96/96/0*7QP0iCr4FE1dJI10.jpg)](https://medium.com/@shishirsub10?source=post_page-----80961b2b551b----------------------)[Shishir Subedi](https://medium.com/@shishirsub10?source=post_page-----80961b2b551b----------------------)Follow[Aug 12](https://medium.com/@shishirsub10/tryhackme-help-bears-80961b2b551b?source=post_page-----80961b2b551b----------------------) · 5 min read

Link: [https://tryhackme.com/room/helpbears](https://tryhackme.com/room/helpbears)

Introduction
------------

<img alt="Image for post" class="t u v cb aj" src="https://miro.medium.com/max/2124/1\*rx1agjUj2iTBEk3qTge-KA.png" width="1062" height="445" srcSet="https://miro.medium.com/max/552/1\*rx1agjUj2iTBEk3qTge-KA.png 276w, https://miro.medium.com/max/1104/1\*rx1agjUj2iTBEk3qTge-KA.png 552w, https://miro.medium.com/max/1280/1\*rx1agjUj2iTBEk3qTge-KA.png 640w, https://miro.medium.com/max/1400/1\*rx1agjUj2iTBEk3qTge-KA.png 700w" sizes="700px"/>

The introduction says that the BEARS need our help to solve a few challenges.

FLAG 1
------

Download the file & get going…

And the downloaded file contains:

```
É=-~-~\[\],ó=-~É,Ë=É<<É,þ=Ë+~\[\];Ì=(ó-ó)\[Û=(''+{})\[É+ó\]+(''+{})\[ó-É\]+(\[\].ó+'')\[ó-É\]+(!!''+'')\[ó\]+({}+'')\[ó+ó\]+(!''+'')\[ó-É\]+(!''+'')\[É\]+(''+{})\[É+ó\]+({}+'')\[ó+ó\]+(''+{})\[ó-É\]+(!''+'')\[ó-É\]\]\[Û\];Ì(Ì((!''+'')\[ó-É\]+(!''+'')\[ó\]+(!''+'')\[ó-ó\]+(!''+'')\[É\]+((!''+''))\[ó-É\]+(\[\].$+'')\[ó-É\]+'\\''+''+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(þ)+(É+ó)+'\\\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\\\'+(ó-É)+(ó+ó)+(É)+'\\\\'+(ó-É)+(É+ó)+(þ)+'\\\\'+(ó-É)+(É+ó)+(É+ó)+'\\\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(É+ó)+(ó-ó)+'\\\\'+(É+É)+(þ)+'\\\\'+(ó-É)+(ó-ó)+(É+ó)+'\\\\'+(ó-É)+(É+ó)+(ó+ó)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(ó-É)+(ó+ó)+(É)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(ó-É)+(þ)+(É)+'\\\\'+(É+É)+(ó-ó)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(É+É)+(ó-ó)+'\\\\'+(ó-É)+(É+ó)+(É+ó)+'\\\\'+(ó-É)+(É+ó)+(þ)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(É+É)+(ó-ó)+'\\\\'+(ó-É)+(É+É)+(É+É)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(É+É)+(ó-ó)+'\\\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(ó-É)+(ó+ó)+(ó)+'\\\\'+(ó-É)+(ó+ó)+(ó)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(É+É)+(þ)+'\\\\'+(É+ó)+(ó-É)+'\\\\'+(þ)+(ó)+'\\\\'+(ó-É)+(É+ó)+(ó-É)+'\\\\'+(ó-É)+(É+É)+(ó+ó)+'\\\\'+(É+ó)+(ó-ó)+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(þ)+(É+ó)+'\\\\'+(þ)+(É+ó)+'\\\\'+(É+É)+(þ)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(ó-É)+(É+ó)+(þ)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(ó-É)+(É+ó)+(þ)+'\\\\'+(ó+ó)+(ó-É)+'\\\\'+(ó+ó)+(É)+'\\\\'+(ó+ó)+(ó)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(ó-É)+(É+ó)+(þ)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(É+É)+(þ)+'\\\\'+(É+ó)+(ó-É)+'\\\\'+(ó-É)+(þ)+(ó)+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(ó-É)+(ó+ó)+(É)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(É+ó)+(ó-ó)+'\\\\'+(É+É)+(þ)+'\\\\'+(ó-É)+(É+É)+(É)+'\\\\'+(ó-É)+(ó+ó)+(É)+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(ó-É)+(ó+ó)+(ó+ó)+'\\\\'+(ó-É)+(É+ó)+(þ)+'\\\\'+(É+É)+(þ)+'\\\\'+(É+ó)+(ó-É)+'\\\\'+(þ)+(ó)+'\\\\'+(ó-É)+(þ)+(É+ó)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(ó-É)+(ó+ó)+(ó)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(ó-É)+(þ)+(ó)+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(ó-É)+(ó+ó)+(É)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(É+ó)+(ó-ó)+'\\\\'+(É+É)+(þ)+'\\\\'+(ó-É)+(É+É)+(ó+ó)+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(ó-É)+(É+ó)+(ó-É)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(É+ó)+(ó+ó)+'\\\\'+(É+ó)+(ó+ó)+'\\\\'+(É+ó)+(ó+ó)+'\\\\'+(É+É)+(þ)+'\\\\'+(É+ó)+(ó-É)+'\\\\'+(þ)+(ó)+'\\\\'+(ó-É)+(þ)+(É+ó)+'\\'')())()
```

It looks like Obfuscated JS.

While searching around, i came across [this article.](https://stackoverflow.com/questions/20884577/how-to-deobfuscate-javascript)

```
É=-~-~\[\],ó=-~É,Ë=É<<É,þ=Ë+~\[\];Ì=(ó-ó)\[Û=(''+{})\[É+ó\]+(''+{})\[ó-É\]+(\[\].ó+'')\[ó-É\]+(!!''+'')\[ó\]+({}+'')\[ó+ó\]+(!''+'')\[ó-É\]+(!''+'')\[É\]+(''+{})\[É+ó\]+({}+'')\[ó+ó\]+(''+{})\[ó-É\]+(!''+'')\[ó-É\]\]\[Û\];Ì(Ì((!''+'')\[ó-É\]+(!''+'')\[ó\]+(!''+'')\[ó-ó\]+(!''+'')\[É\]+((!''+''))\[ó-É\]+(\[\].$+'')\[ó-É\]+'\\''+''+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(þ)+(É+ó)+'\\\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\\\'+(ó-É)+(ó+ó)+(É)+'\\\\'+(ó-É)+(É+ó)+(þ)+'\\\\'+(ó-É)+(É+ó)+(É+ó)+'\\\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(É+ó)+(ó-ó)+'\\\\'+(É+É)+(þ)+'\\\\'+(ó-É)+(ó-ó)+(É+ó)+'\\\\'+(ó-É)+(É+ó)+(ó+ó)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(ó-É)+(ó+ó)+(É)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(ó-É)+(þ)+(É)+'\\\\'+(É+É)+(ó-ó)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(É+É)+(ó-ó)+'\\\\'+(ó-É)+(É+ó)+(É+ó)+'\\\\'+(ó-É)+(É+ó)+(þ)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(É+É)+(ó-ó)+'\\\\'+(ó-É)+(É+É)+(É+É)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(É+É)+(ó-ó)+'\\\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(ó-É)+(ó+ó)+(ó)+'\\\\'+(ó-É)+(ó+ó)+(ó)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(É+É)+(þ)+'\\\\'+(É+ó)+(ó-É)+'\\\\'+(þ)+(ó)+'\\\\'+(ó-É)+(É+ó)+(ó-É)+'\\\\'+(ó-É)+(É+É)+(ó+ó)+'\\\\'+(É+ó)+(ó-ó)+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(þ)+(É+ó)+'\\\\'+(þ)+(É+ó)+'\\\\'+(É+É)+(þ)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(ó-É)+(É+ó)+(þ)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(ó-É)+(É+ó)+(þ)+'\\\\'+(ó+ó)+(ó-É)+'\\\\'+(ó+ó)+(É)+'\\\\'+(ó+ó)+(ó)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(ó-É)+(É+ó)+(þ)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(É+É)+(þ)+'\\\\'+(É+ó)+(ó-É)+'\\\\'+(ó-É)+(þ)+(ó)+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(ó-É)+(ó+ó)+(É)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(É+ó)+(ó-ó)+'\\\\'+(É+É)+(þ)+'\\\\'+(ó-É)+(É+É)+(É)+'\\\\'+(ó-É)+(ó+ó)+(É)+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(ó-É)+(ó+ó)+(ó+ó)+'\\\\'+(ó-É)+(É+ó)+(þ)+'\\\\'+(É+É)+(þ)+'\\\\'+(É+ó)+(ó-É)+'\\\\'+(þ)+(ó)+'\\\\'+(ó-É)+(þ)+(É+ó)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(ó-É)+(ó+ó)+(ó)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(ó-É)+(þ)+(ó)+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(ó-É)+(É+É)+(É+ó)+'\\\\'+(ó-É)+(ó+ó)+(É)+'\\\\'+(ó-É)+(ó+ó)+(É+É)+'\\\\'+(É+ó)+(ó-ó)+'\\\\'+(É+É)+(þ)+'\\\\'+(ó-É)+(É+É)+(ó+ó)+'\\\\'+(ó-É)+(É+É)+(ó-É)+'\\\\'+(ó-É)+(É+ó)+(ó-É)+'\\\\'+(ó-É)+(É+ó)+(É+É)+'\\\\'+(É+ó)+(ó+ó)+'\\\\'+(É+ó)+(ó+ó)+'\\\\'+(É+ó)+(ó+ó)+'\\\\'+(É+É)+(þ)+'\\\\'+(É+ó)+(ó-É)+'\\\\'+(þ)+(ó)+'\\\\'+(ó-É)+(þ)+(É+ó)+'\\'')()).toString()
```

And just deleting the last ‘()’ and replacing with toString() gives us.

<img alt="Image for post" class="t u v cb aj" src="https://miro.medium.com/max/1396/1\*A968Wzq\_GyRuTOXS9nEznw.png" width="698" height="146" srcSet="https://miro.medium.com/max/552/1\*A968Wzq\_GyRuTOXS9nEznw.png 276w, https://miro.medium.com/max/1104/1\*A968Wzq\_GyRuTOXS9nEznw.png 552w, https://miro.medium.com/max/1280/1\*A968Wzq\_GyRuTOXS9nEznw.png 640w, https://miro.medium.com/max/1396/1\*A968Wzq\_GyRuTOXS9nEznw.png 698w" sizes="698px"/>

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

<img alt="Image for post" class="t u v cb aj" src="https://miro.medium.com/max/1274/1\*wGxqFEly5AQyRqK4m\_Wr6Q.png" width="637" height="510" srcSet="https://miro.medium.com/max/552/1\*wGxqFEly5AQyRqK4m\_Wr6Q.png 276w, https://miro.medium.com/max/1104/1\*wGxqFEly5AQyRqK4m\_Wr6Q.png 552w, https://miro.medium.com/max/1274/1\*wGxqFEly5AQyRqK4m\_Wr6Q.png 637w" sizes="637px"/>

FLAG 3
------

There’s a flag hidden somewhere. Can you find it?

Looking at the files that i have downloaded, i didn't find anything that might be hidden. As the challenge has a stegno tag, I noticed a image on the Introduction section.

So I downloaded the image using wget.

```
wget [https://i.ibb.co/WD6ftr9/bear.jpg](https://i.ibb.co/WD6ftr9/bear.jpg)
```

Using exiftool on the image, i didnot find anything interesting.

```
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

```
strings bear.jpg
```

As it was a jpeg image, i tried extracting the hidden data, if there was any, using steghide with blank password.

```
$ steghide extract -sf bear.jpg   
Enter passphrase:   
steghide: could not extract any data with that passphrase!
```

So I decided to bruteforce the password using stegcrack and with rockyou.txt wordlist.

```
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

```
$ steghide extract -sf bear.jpg  
Enter passphrase:   
wrote extracted data to "challenge.txt".
```

Looking at file using cat

```
$ cat challenge.txt   
Grizzly‌‌‌‌‍!‌‌‌‌‌
```

Looking the file challenge.txt in Vim

```
<200c><200c><200c><200c><200d><200c><200d><202c>Grizzly<200c><200c><200c><200c><200d><202c><feff><200c><200c><200c><200c><200c><200d><202c><200c><200d><200c><200c><200c><200c><200d><202c><200d><feff><200c><200c><200c><200c><200c><feff><202c><202c><200c><200c><200c><200c><200c><202c><200c><200c><200c><200c><200c><200c><200c><202c><202c><202c><200c><200c><200c><200c><200c><feff><202c><feff><200c><200c><200c><200c><200d><feff><feff><200d><200c><200c><200c><200c><200c><feff><202c><200d><200c><200c><200c><200c><200c><feff><200d><200c><200c><200c><200c><200c><200c><feff><feff><feff><200c><200c><200c><200c><200d><feff><feff><200d><200c><200c><200c><200c><200c><feff><200d><feff><200c><200c><200c><200c><200c><202c><202c><feff><200c><200c><200c><200c><200d><200c><202c><feff><200c><200c><200c><200c><200d><feff><200c><200c><200c><200c><200c><200c><200d><200c><202c><200c><200c><200c><200c><200c><200c><feff><200c><feff>!<200c><200c><200c><200c><200c><feff><feff><202c><200c><200c><200c><200c><200d><feff><200d><200d><200c><200c><200c><200c><200c><feff><200d><feff><200c><200c><200c><200c><200c><feff><200d><200c><200c><200c><200c><200c><200d><feff><200d><202c><200c><200c><200c><200c><200d><feff><200d><200c><200c><200c><200c><200c><200c><feff><feff><200c><200c><200c><200c><200c><200d><feff><202c><200d><200c><200c><200c><200c><200d><feff><200d><200d><200c><200c><200c><200c><200d><202c><202c><200c><200c><200c><200c><200c><200d><200d><feff><feff><200c><200c><200c><200c><200d><feff><feff><200d><200c><200c><200c><200c><200d><feff><200d><202c><200c><200c><200c><200c><200c><202c><200d><feff><200c><200c><200c><200c><200c><feff><200d><feff><200c><200c><200c><200c><200d><feff><feff><200c><200c><200c><200c><200c><200d><feff><200d><200d><200c><200c><200c><200c><200d><feff><feff><200d><200c><200c><200c><200c><200d><feff><200c><feff><200c><200c><200c><200c><200c><202c><200d><202c><200c><200c><200c><200c><200d><feff><200c><200c><200c><200c><200c><200c><200d><202c><feff><200c><200c><200c><200c><200c><200d><202c><feff><200c>
```

I was familiar with the data hiding using unicode spaces and normal spaces. But this was new to me. So I searched around and found [this website](https://330k.github.io/misc_tools/unicode_steganography.html) explaining the use of zero width character for stegnography and also has a decoder.

Decoder on the Website

<img alt="Image for post" class="t u v cb aj" src="https://miro.medium.com/max/3186/1\*VDkd\_11Z9NjGt2PCsnqPPQ.png" width="1593" height="599" srcSet="https://miro.medium.com/max/552/1\*VDkd\_11Z9NjGt2PCsnqPPQ.png 276w, https://miro.medium.com/max/1104/1\*VDkd\_11Z9NjGt2PCsnqPPQ.png 552w, https://miro.medium.com/max/1280/1\*VDkd\_11Z9NjGt2PCsnqPPQ.png 640w, https://miro.medium.com/max/1456/1\*VDkd\_11Z9NjGt2PCsnqPPQ.png 728w, https://miro.medium.com/max/1632/1\*VDkd\_11Z9NjGt2PCsnqPPQ.png 816w, https://miro.medium.com/max/1808/1\*VDkd\_11Z9NjGt2PCsnqPPQ.png 904w, https://miro.medium.com/max/1984/1\*VDkd\_11Z9NjGt2PCsnqPPQ.png 992w, https://miro.medium.com/max/2000/1\*VDkd\_11Z9NjGt2PCsnqPPQ.png 1000w" sizes="1000px"/>

But i was having problem copying the text. So i used a tool called xclip.

Xclip can be install from apt.

```
$ apt install xclip
```

Using xclip, I copied the content of the file challenge.txt and pasted on the site .

```
$ cat challenge.txt | xclip -selection clipboard
```

After it decoded the content, I downloaded a file.

<img alt="Image for post" class="t u v cb aj" src="https://miro.medium.com/max/2362/1\*520Kdq-lc2SBLyb-mLpyAw.png" width="1181" height="370" srcSet="https://miro.medium.com/max/552/1\*520Kdq-lc2SBLyb-mLpyAw.png 276w, https://miro.medium.com/max/1104/1\*520Kdq-lc2SBLyb-mLpyAw.png 552w, https://miro.medium.com/max/1280/1\*520Kdq-lc2SBLyb-mLpyAw.png 640w, https://miro.medium.com/max/1400/1\*520Kdq-lc2SBLyb-mLpyAw.png 700w" sizes="700px"/>

Looking at the contents of the downloaded file

```
^[@F](http://twitter.com/F)^[@l](http://twitter.com/l)^[@a](http://twitter.com/a)^[@g](http://twitter.com/g)^@:^@ ^@\*^@;^@}^[@9](http://twitter.com/9)^[@4](http://twitter.com/4)^@?^@}^[@7](http://twitter.com/7)^@+^[@K](http://twitter.com/K)^[@p](http://twitter.com/p)^[@H](http://twitter.com/H)^[@3](http://twitter.com/3)^@>^[@u](http://twitter.com/u)^[@7](http://twitter.com/7)^[@4](http://twitter.com/4)^[@v](http://twitter.com/v)^[@t](http://twitter.com/t)^@<^[@y](http://twitter.com/y)^[@u](http://twitter.com/u)^[@h](http://twitter.com/h)^[@\_](http://twitter.com/_)^@}^[@v](http://twitter.com/v)^@'^[@7](http://twitter.com/7)^@|^[@u](http://twitter.com/u)^@}^[@s](http://twitter.com/s)^@&^[@p](http://twitter.com/p)^[@l](http://twitter.com/l)^[@l](http://twitter.com/l)
```

Clearing the gibberish text

```
Flag: \*;}94?}7+KpH3>u74vt<yuh\_}v'7|u}s&pll
```

I was having strong doubts that it doesn't look like a flag, but I couldn't resist and submitted the flag. And the flag was incorrect.

It looked like a cipher, and just by inspection I thought it was rot47 cipher. So I went to [this site](https://www.dcode.fr/rot-47-cipher) to decode the cipher.

<img alt="Image for post" class="t u v cb aj" src="https://miro.medium.com/max/1602/1\*rbGElIz9B5mnuiSrJjAnNQ.png" width="801" height="205" srcSet="https://miro.medium.com/max/552/1\*rbGElIz9B5mnuiSrJjAnNQ.png 276w, https://miro.medium.com/max/1104/1\*rbGElIz9B5mnuiSrJjAnNQ.png 552w, https://miro.medium.com/max/1280/1\*rbGElIz9B5mnuiSrJjAnNQ.png 640w, https://miro.medium.com/max/1400/1\*rbGElIz9B5mnuiSrJjAnNQ.png 700w" sizes="700px"/>

And now the output looked familiar. It was a base64 encoded string. So i decoded the string and finally got the final flag.

<img alt="Image for post" class="t u v cb aj" src="https://miro.medium.com/max/1212/1\*ATgiSSjoVZZU1GDBfl0FWQ.png" width="606" height="126" srcSet="https://miro.medium.com/max/552/1\*ATgiSSjoVZZU1GDBfl0FWQ.png 276w, https://miro.medium.com/max/1104/1\*ATgiSSjoVZZU1GDBfl0FWQ.png 552w, https://miro.medium.com/max/1212/1\*ATgiSSjoVZZU1GDBfl0FWQ.png 606w" sizes="606px"/>

Thank you for reading the write up. Reply if you have any suggestions regarding the write up. Hope you have enjoyed reading as much as i have enjoyed writing it.
