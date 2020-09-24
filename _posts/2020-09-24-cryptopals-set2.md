---
title: "Cryptopals Set 2"
last_modified_at: 2020-09-24T2:35:02-05:00
categories:
  - crypto
author_profile: false
tags:
  - python
  - crypto
  - AES
  - CBC
---

# Set 2
Head over to [https://cryptopals.com/sets/2](https://cryptopals.com/sets/2) for questions.

## challenge 9 (Implement PKCS#7 padding)

```python
#!/usr/bin/python3

#Break ciphertext into blocks of blocksize
def break_cipher(con,blocksize):
	lis = []
	for i in range(0,len(con),blocksize):
		#print(con[i:i+16])
		lis.append(con[i:i+blocksize])
	
	return lis
#padding according to pad_val
def padding(con,blocksize,pad_val):
	if blocksize > pad_val:
		print("blocksize must be small")
		return
	j = 0
	for i in con:
		diff = pad_val - len(i)
		if diff > 0:
			ch = b'\x04'
			con[j] += ch * diff

		j +=1	

con = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccdddddddddddddddd'
blocksize = 8
pad_val = 20
lis = break_cipher(con,blocksize)
padding(lis,blocksize,pad_val)
print((lis))
```

## challenge 10

```python
from Crypto.Cipher import AES
import codecs

#we have to encrypt con with key
con = b'''\x94\xde2\x04N\x97{\xd7\x19\x8e:"\xb3\x83\x1f~ ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04'''
key = b"YELLOW SUBMARINE"

# divide into chunks of 16 and returns list 
def break_cipher(con,blocksize):
	lis = []
	for i in range(0,len(con),blocksize):
		lis.append(con[i:i+blocksize])
	
	return lis

#check for padding
def padding(con,blocksize,pad_val):
	if blocksize > pad_val:
		print("blocksize must be small than the padding value")
		return
	j = 0
	for i in con:
		diff = pad_val - len(i)
		if diff > 0:
			ch = b'\x04'
			con[j] += ch * diff

		j +=1	

# xoring with the plaintext and ciphertext(does with IV inititally); returns intermediate value
def xoring(plaintext,ciphertext):
    out = ''
    for i in range(0,16):
        out1 = (ciphertext[i] ^ plaintext[i])
        #to maintain length for eg 4 in int = 0x4 which will be problem as we want exactly 16 bytes value, so concating 0 making it 04
        if len(str(hex(out1)).encode()) == 3:
            out += '0'
            out += str(hex(out1)[2:])
        else:
            out += str(hex(out1)[2:])
    return out  #returns 32 byte string in hex

#using encryption from the libary Crypto
def encrypted_form(plain,key):
    plained = codecs.decode(plain,'hex') #changing hex to binary
    decipher = AES.new(key, AES.MODE_ECB)
    dec = decipher.encrypt(plained)
    return dec

blocksize = 16
pad_val = 16

lis = break_cipher(con,blocksize)  #breaking plaintext into block of blocksize ie 16
padding(lis,blocksize,pad_val)      # padding if the blocksize is not equal to 16

ciphertext = b'\x00' *16 #initialization vector 
encodedtext = b'' # output

for value in lis:    
    tmp = xoring(value,ciphertext)
    ciphertext = encrypted_form(tmp,key)    
    encodedtext += ciphertext

#decrypting using library should give what we started with
decipher2 = AES.new(key, AES.MODE_CBC)
print(decipher2.decrypt(encodedtext))
```

```python
b"\x8f\xa3\x17\x80\xe25\xddt\xa1\xeeM=\x8b\xab4\xd0 ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"
```

## Challenge 11

```python
from Crypto.Cipher import AES
import codecs
import random
import string

blocksize = 16
pad_val = 16
# divide into chunks of 16 and returns list 
def break_cipher(con,blocksize=blocksize):
    lis = []
    for i in range(0,len(con),blocksize):
        lis.append(con[i:i+blocksize])
    
    return lis

#check for padding
def padding(con,blocksize=blocksize,pad_val=pad_val):
    if blocksize > pad_val:
        print("blocksize must be small than the padding value")
        return
    j = 0
    for i in con:
        diff = pad_val - len(i)
        if diff > 0:
            ch = b'\x04'
            con[j] += ch * diff

        j +=1	

# xoring with the plaintext and ciphertext(does with IV inititally); returns intermediate value
def xoring(plaintext,ciphertext):
    out = ''
    for i in range(0,16):
        out1 = (ciphertext[i] ^ plaintext[i])
        #to maintain length for eg 4 in int = 0x4 which will be problem as we want exactly 16 bytes value, so concating 0 making it 04
        if len(str(hex(out1)).encode()) == 3:
            out += '0'
            out += str(hex(out1)[2:])
        else:
            out += str(hex(out1)[2:])
    return out

def aes_cbc_encrypt(con,key,ciphertext):
    #using encryption from the libary Crypto
    print("encrypting using cbc")
    def encrypted_form(plain,key):
        plained = codecs.decode(plain,'hex') #changing hex to binary
        decipher = AES.new(key, AES.MODE_ECB)
        dec = decipher.encrypt(plained)
        return dec

    encodedtext = b'' # output

    lis = break_cipher(con)  #breaking plaintext into block of blocksize ie 16
    padding(lis)      # padding if the blocksize is not equal to 16

    for value in lis:    
        tmp = xoring(value,ciphertext)
        ciphertext = encrypted_form(tmp,key)    
        encodedtext += ciphertext
    return encodedtext

def aes_ecb_encryption(key,con):
    print("encrypting using ECB")
    #decrypting using library should give what we started with
    out = b''
    lis = break_cipher(con,blocksize)
    padding(lis,blocksize,pad_val)
    for text in lis:
        decipher2 = AES.new(key, AES.MODE_ECB)
        msg = decipher2.encrypt(text)
        out += msg
    return out

def keygen(stringLength=16):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

key = keygen().encode()

#we have to encrypt con with key
con = b'''\x94\xde2\x04N\x97{\xd7\x19\x8e:"\xb3\x83\x1f~ ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04'''
ciphertext = keygen(16).encode() #initialization vector 

#appending random 10 bytes at end and start of con
con = keygen(10).encode() + con + keygen(10).encode()

#random number generation
if (random.randint(0, 1)) == 0:
        ciphertext = aes_ecb_encryption(key,con)
else:
    ciphertext = aes_cbc_encrypt(con,key,ciphertext)

#Detection phase
#check for ecb as two same blocks will give same ciphertext
# check is done using 16 bytes block. Can be reduced to 4 or 8 
lis = break_cipher(ciphertext,16)
length = len(lis)
count = 0
for i in range(0,length):
    for j in range(0,length):
        if i == j:
            continue
        if lis[i] == lis[j]:
            count += 1

if count > 0:
    print("this might be ECB encrypted as " + str(count) + " blocks are found similar")
if count == 0:
    print(" it is CBC encrypted as no 2 blocks are found similar")
```

## Challenge 12

```python
from Crypto.Cipher import AES
import codecs
import random
import string

blocksize = 16
pad_val = 16
# divide into chunks of 16 and returns list 
def break_cipher(con,blocksize=blocksize):
    lis = []
    for i in range(0,len(con),blocksize):
        lis.append(con[i:i+blocksize])
    
    return lis

#check for padding
def padding(con,blocksize=blocksize,pad_val=pad_val):
    if blocksize > pad_val:
        print("blocksize must be small than the padding value")
        return
    j = 0
    for i in con:
        diff = pad_val - len(i)
        if diff > 0:
            ch = b'\x04'
            con[j] += ch * diff

        j +=1	

# xoring with the plaintext and ciphertext(does with IV inititally); returns intermediate value
def xoring(plaintext,ciphertext):
    out = ''
    for i in range(0,16):
        out1 = (ciphertext[i] ^ plaintext[i])
        #to maintain length for eg 4 in int = 0x4 which will be problem as we want exactly 16 bytes value, so concating 0 making it 04
        if len(str(hex(out1)).encode()) == 3:
            out += '0'
            out += str(hex(out1)[2:])
        else:
            out += str(hex(out1)[2:])
    return out

def aes_ecb_encryption(key,con):
    out = b''
    lis = break_cipher(con,blocksize)
    padding(lis,blocksize,pad_val)
    for text in lis:
        decipher2 = AES.new(key, AES.MODE_ECB)
        msg = decipher2.encrypt(text)
        out += msg
    return out

def keygen(stringLength=16):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

key = keygen().encode()

#we have to encrypt con with key
con = b'''A''' *15 #+ b"Rollin' in my 5."
ciphertext = keygen(16).encode() #initialization vector 

#appending random 10 bytes at end and start of con - it is disabled for this exercise
#con = keygen(10).encode() + con + keygen(10).encode()

con = b'''A''' *15
con64 = b"""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
base64con = codecs.decode(con64,'base64')
con +=base64con
ciphertext = aes_ecb_encryption(key,con)
dic ={}
secret = ''
for j in range(0,len(con)-15): #length of secret
    res = aes_ecb_encryption(key,con)
    for i in range(0,128):
        dic[chr(i)] = aes_ecb_encryption(key,b'A'*15 + chr(i).encode())
        if res[0:16] == dic[chr(i)][0:16]:
            #print('match found : ' + chr(i) + str(i))
            secret += chr(i)
            con = con.decode()
            #deleting every 16th character per match
            lis = list(con)
            del(lis[15])
            con = ''.join(lis)
            con  = con.encode()
        
print(secret)
```

Output

```python
b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
```

# TODO
Other Questions in this set and all the other sets are on my todo list. I will be updating the content after I solve them.