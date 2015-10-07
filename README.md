# Practical AES #

#Introduction#

PracticalAES is a function designed to encrypt/decrypt binary files given a cipher key with accordance to AES-128 in both ECB
and CBC operational modes.  It is designed with the intent of simplying the effort requried by the user with regards to not 
only encrypting and decryptiong binary files, but in addition being able to easily lookup and extract files within the binary
code (e.x. .txt, .sql, etc).  

The executable, once compiled, is designed to be easily operated by users.  The EBC mode is enabled by default, but adding an
additional argument to the end automatically enables CBC mode.  The program itself uses no outside libraries, but it uses the
non-standard function itoa().  In the case of your compiler not supporting itoa(), the function can be easily replaced
with a custom, similar itoa() function.

#Usage#

PracticalAES currently supports encryption and decryption for both EBC and CBC modes.  The command to perform said operations
via command line, once compiled, are as followed:

>EBC Encryption: practicalaes.exe e cipherkey.txt binaryfile.bin
  
>CBC Encryption: practicalaes.exe e cipherkey.txt binaryfile.bin ivfile.bin

>EBC Decryption: practicalaes.exe d cipherkey.txt binaryfile.bin
  
>CBC Decryption: practicalaes.exe d cipherkey.txt binaryfile.bin ivfile.bin

Encrypting/Decrypting binary files is fairly straightforward, where the cipher key is to be written in a text file, while the
file to be encrypted/decrypted as well as the initialization vector (for CBC only) are to be written in bytes.  Future 
versions of practicalaes will likely require the cipherkey to be written in bytes as well for parity reasons.  The binary 
file extention is not required, as byte files with no exntention can be used as well.

#Results#

Below are a few tests to demonstrate the accuracy of practicalaes for both the EBC and CBC modes.

*EBC Encryption*

Binary File:  
32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34  
89 A7 D9 8E 98 98 7F 97 36 D9 8C FB 38 23 23 98  
27 66 98 C7 9D 87 76 9D 09 34 8D 86 88 78 D1 10  

Cipher Key:  
2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF F4 3C

Result:  
39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32  
AB 25 81 26 96 E2 AB 09 F3 F5 7F D5 4E 05 A3 04  
05 DF 61 12 9B 8B 48 E3 0C 8C 96 55 14 FB AE 8B  

*CBC Encryption*

Binary File:  
32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34  
89 A7 D9 8E 98 98 7F 97 36 D9 8C FB 38 23 23 98  
27 66 98 C7 9D 87 76 9D 09 34 8D 86 88 78 D1 10  

Cipher Key:  
2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF F4 3C

Initialization Vector:  
43 F4 3D 32 90 19 3E 4B 92 C9 1A 3D 0F FF 2D 7B

Result:  
E8 DE C5 0E 7A D0 26 A8 2C 0D 25 0F 4A 18 C3 BF  
EF 2E 2B 5A 1B 65 07 FA 12 A4 23 67 BA 88 F6 48  
85 86 40 1B B3 4B 8E 56 8B D4 8E 33 E6 95 75 EE  



