---
title: "Cryptopals Set 1"
last_modified_at: 2020-09-24T2:35:02-05:00
categories:
  - crypto
author_profile: false
tags:
  - python
  - crypto
  - base64
  - AES
  - CBC
---


# Set 1
Head over to [https://cryptopals.com/sets/1](https://cryptopals.com/sets/1) for questions.


## Challenge 1

```python
import codecs
hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
temp = codecs.encode(codecs.decode(hex,'hex'),'base64')
print(temp)
```

## Challenge 2

```python
import codecs
var1 = "1c0111001f010100061a024b53535009181c"
var2 = "686974207468652062756c6c277320657965"
tmp2 = codecs.decode(var2,'hex')
tmp1 = codecs.decode(var1,'hex')
i = 0
out = ''
for j in tmp1:
out += (chr(j ^ tmp2[i]))
i +=1
out = out.encode()
tmp3 = codecs.encode(out,'hex')
print(tmp3)
```

## Challenge 3

```python
import codecs
var = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
tmp = codecs.decode(var,'hex')
count = 0
tmpnum ={}
#using characters for 0 to } as key
for k in range(48,125):
out = ''
for j in tmp:
out += (chr(k ^ j))
out = out.encode()
#creating an dict to save the count of most repeting characters
all_freq = {}
for i in out:
if i in all_freq:
all_freq[i] += 1
else:
all_freq[i] = 1
tmpnum.update({chr(k):all_freq.get(ord('e'),0)+ all_freq.get(ord('a'),0)+all_freq.get(ord('t'),0)+all_freq.get(ord('o'),0)+all_freq.get(ord('i'),0)+all_freq.get(ord('r'),0)})
#ordering the dictionary according the count
tmpnum={k: v for k, v in sorted(tmpnum.items(), key=lambda item: item[1],reverse=True)}
#using only top 10 as a key to generate the output
top10 = list(tmpnum.keys())[:10]
for val in top10:
out =''
for j in tmp:
out += chr(ord(val)^j)
out = out.encode()
print(out)
```

Output

```python
b'Maaegi.CM)}.bgek.o.~a{j.ah.loma' 
`**b"Cooking MC's like a pound of bacon"** 
b'Ieeacdm*GI-y*fcao*k*ze\\x7fdn*el*hkied'
b'Eiimoha&KE!u&jomc&g&vishb&i`&dgeih'
b'Xttpru|;VX<h;wrp~;z;ktnu\x7f;t};yzxtu'
b'^rrvtsz=P^:n=qtvx=|=mrhsy=r{=\x7f|~rs'
b"Dhhlni`'JD t'knlb'f'whric'ha'efdhi" 
b'Bnnjhof!LB&r!mhjd!`!qntoe!ng!c`bno' 
b'Gkkomjc$IG#w$hmoa$e$tkqj`$kb$fegkj'
b'Yuuqst}:WY=i:vsq\x7f:{:juot~:u|:x{yut'
```

## Challenge 4

```python
import codecs

def func(var):
	tmp = codecs.decode(var,'hex')
	tmpnum ={} 
	#using characters for 0 to } as key
	for k in range(48,125):
		out = ''
		for j in tmp:
				#print(j)
				out += (chr(k ^ j))
		out = out.encode()
		#creating an dict to save the count of most repeting characters
		all_freq = {} 
		for i in out: 
				if i in all_freq: 
					all_freq[i] += 1
				else: 
					all_freq[i] = 1
		tmpnum.update({chr(k):all_freq.get(ord('e'),0)+ all_freq.get(ord('a'),0)+all_freq.get(ord('t'),0)+all_freq.get(ord('o'),0)+all_freq.get(ord('i'),0)+all_freq.get(ord('r'),0)})
	#ordering the dictionary according the count
	tmpnum={k: v for k, v in sorted(tmpnum.items(), key=lambda item: item[1],reverse=True)}
	#using only top 10 as a key to generate the output
	top10 = list(tmpnum.keys())[:10]
	for val in top10:
		check(val,tmp)

def check(val,tmp):		
		out =''
		for j in tmp:
			out += chr(ord(val)^j)
		out = out.encode()
		#print((type(out[5])))
		for ch in out:
			#print(ch,type(ch))
			if ch > 129 or ch < 20 and ch !=10:
				return

		#looking for some common words	
		if 'the ' in str(out) or 'an ' in str(out):
			print(out)

# link for 4.txt https://cryptopals.com/static/challenge-data/4.txt
f = open('4.txt','r')
for line in f.readlines():
	func(line.rstrip())
```

```
Output: b'Now that the party is jumping\n'
```

## Challenge 5

```python
import codecs
msg =b'''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
key = b'ICE'
out = ''
i = 0
for ch in msg:
	out += (chr(ch ^ (key[i%3])))
	i+=1
print(out.encode())
print(codecs.encode(out.encode(),'hex'))
```

Output:

```
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
```

## Challenge 6 

```python
import codecs
import operator

f = open('6.txt','r')
con = f.read()
con = codecs.decode(con.encode(),'base64')

#hamming distance calculation
def hamming(str1,str2):
	i = 0
	dist = 0
	for ch in str1:
		ch = '{0:8b}'.format(ch)
		tmp = '{0:8b}'.format(str2[i])
		for k in range (0,len(ch)):
			if ch[k] != tmp[k]:
				dist +=1
		i +=1
	return dist

#check if the ouptut contains ascii value
def check(val,tmp):		
		out =''
		for j in tmp:
			out += chr(ord(val)^j)
		out = out.encode()
		for ch in out:
			# greater than DEL, less than 20 but excluding new line
			if (ch > 129 or ch < 20) and ch !=10:
				return
		#if all conditions are satisfied print output
	#	print(val)
	#	print(out)	

#calculation of hamming distance for diffent key value ( from 2 to 40)
dic = {}
for i in range (2,41):
	tmp1 = hamming(con[:i],con[i:2*i])
	#rint(tmp1)
	tmp2 = hamming(con[:i],con[2*i:3*i])
	tmp3 = hamming(con[:i],con[3*i:4*i])
	tmp4 = hamming(con[i:2*i],con[2*i:3*i])
	tmp5 = hamming(con[i:2*i],con[3*i:4*i])
	tmp6 = hamming(con[2*i:3*i],con[3*i:4*i])
	#dist = (tmp1+tmp2+tmp3+tmp4+tmp5+tmp6)/6*i
	dist = (tmp1/i +tmp3/i+ tmp2/i+tmp4/i+tmp5/i+tmp6/i)/6

	dic.update({str(i):dist})

#sorting the dictionary
dic = {k: v for k, v in sorted(dic.items(), key=lambda item: item[1])}
print(dic)
#selecting very first value which distance is mimimum
len_key = int(list(dic.keys())[0])
len_key =29
brk = [] # breaking into 5 bytes as keysize is 5
for i in range(0,len(con),len_key):
	brk.append(con[i:i+len_key])

#rounding up and not using last value in list if it is not equal to length of key
len_brk = len(brk) - (len(brk) % len_key)

#sepearating into groups ie groups of characters in 1st position and second position and so on
grp=[]
for i in range(0,len_key):
	tmp = []
	for j in range(0,len_brk):
		tmp.append(brk[j][i])
	grp.append(tmp)

#function from single character xor ie checks every character and sums the most frequent characrer in the output ie e,a,t,o,i,r and makes a dictionary accordingly
def func(tmp):
	tmpnum ={} 
	#using characters for 0 to } as key
	for k in range(20,127):
		out = ''
		for j in tmp:
				out += (chr(k ^ j))
		out = out.encode()
		#creating an dict to save the count of most repeting characters
		all_freq = {} 
		for i in out: 
				if i in all_freq: 
					all_freq[i] += 1
				else: 
					all_freq[i] = 1
		tmpnum.update({chr(k):all_freq.get(ord('e'),0)+ all_freq.get(ord('a'),0)+all_freq.get(ord('t'),0)+all_freq.get(ord('o'),0)+all_freq.get(ord('i'),0)+all_freq.get(ord('r'),0)})
	#ordering the dictionary according the count
	tmpnum={k: v for k, v in sorted(tmpnum.items(), key=lambda item: item[1],reverse=True)}
	#using only top 10 as a key togenerate the output
	top10 = list(tmpnum.keys())[:10]
	
	#checking the output - returns if it contains illegal characters
	for val in top10:
		check(val,tmp)

#checking the first group to find the key ie list of characters at position 1
for i in range(0,29):
	#print('\n')
	func(grp[i])

#key was obtained manually from above code
def decode():
	msg =con
	key = b"Terminator X: Bring the noise"
	out = ''
	i = 0
	for ch in msg:
		out += (chr(ch ^ (key[i%29])))
		i+=1
	print(out.encode())
decode()
```

Output

```python
b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"
```

## challenge 7

```python
from Crypto.Cipher import AES
import codecs

f = open('7.txt','r')
con = f.read()
con = codecs.decode(con.encode(),'base64')

key = b"YELLOW SUBMARINE"
decipher = AES.new(key, AES.MODE_ECB)
print(decipher.decrypt(con))
```

output:

```python
b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"
```

```bash
#error with openssl
$ openssl aes-128-ecb -md md5 -d -a  -in 7.txt
bad magic number
```

## Challenge 8

```python
from Crypto.Cipher import AES
import codecs

#Break ciphertext into blocks of blocksize
def break_cipher(con,blocksize):
	lis = []
	for i in range(0,len(con),blocksize):
		#print(con[i:i+16])
		lis.append(con[i:i+blocksize])
	
	return lis
#creating dictionary to store line number key and blocksize value pair 
dic = {}
i = 0

#reading from the input file
f = open('8.txt','r')
for lines in f.readlines():
	lines = lines.strip()
	con = codecs.decode(lines,'hex')
	res = break_cipher(con,16)
	dic[i] = res
	i+=1

#set to store line number 
unique = set()

#checking if any block is repeated as with ECB mode for same block with same content gives same ciphertext
length = len(list(dic.keys()))
for i in range(0,length):
	for j in range(0,len(dic[i])):
		for k in range(0,len(dic[i])):
			if j == k:
				continue
			if dic[i][j] == dic[i][k]:
				unique.add(i)

# printing the value of the ECB encrypted line
for i in unique:
	print(dic[i])
```