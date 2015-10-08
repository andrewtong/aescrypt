#Practical AES#

###Introduction###

PracticalAES is a function designed to encrypt/decrypt binary files given a cipher key with accordance to AES-128 in both ECB
and CBC operational modes.  It is designed with the intent of simplying the effort requried by the user with regards to not 
only encrypting and decryptiong binary files, but in addition being able to easily lookup and extract files within the binary
code (e.x. .txt, .sql, etc).  

The executable, once compiled, is designed to be easily operated by users.  The EBC mode is enabled by default, but adding an
additional argument to the end automatically enables CBC mode.  The program itself uses no outside libraries, but it uses the
non-standard function itoa().  In the case of your compiler not supporting itoa(), the function can be easily replaced
with a custom, similar itoa() function.

###Usage###

PracticalAES currently supports encryption and decryption for both EBC and CBC modes.  The command to perform said operations
via command line, once compiled, are as followed:

>EBC Encryption: practicalaes.exe e cipherkey binaryfile  
>CBC Encryption: practicalaes.exe e cipherkey binaryfile ivfile  
>EBC Decryption: practicalaes.exe d cipherkey binaryfile  
>CBC Decryption: practicalaes.exe d cipherkey binaryfile ivfile

Encrypting/Decrypting binary files is fairly straightforward, where the cipher key, binary file to be encrypted/decrypted, as
well as the initialization vector (if CBC is being used) are written in binary files.  The simplest way to do this is to use
a hex editor to enter the data, as shown below.  

![Cipher](https://cloud.githubusercontent.com/assets/10404525/10374070/f03f1ce6-6da5-11e5-8bf4-ee467acaf66f.PNG)

Because reading in hexadecimal is often the most convinient method when operating with AES, practicalAES was designed with
the intent of being able to read hex files to gather the necessary encryption/decryption keys.

![CmdLine](https://cloud.githubusercontent.com/assets/10404525/10374517/6b6be910-6da8-11e5-933e-668af11308fe.PNG)

A sample executable usage is demonstrated in the command line prompt above.  The code is compiled to an executable, of which
I chose to be practicalaes.exe.  The letter 'e' designates that I would like to perform an encryption, while cipher, sample, 
and iv are all binary files respectively referring to the cipher key, file to be encrypted/decrypted, and the initialization
vector all required for AES.  Note that because the iv file was included at the end, the executable performs a CBC 
encryption.  If the last argument was not provided, the executable would perform a EBC encryption.

It is important to keep in mind that the program uses absolute directories.  This is to be changed by the user, in the code.
The variable for this is (char *basedirectory), and the user is expected to alter this to point to the directory that 
contains both the source code and the binary files required for AES.  The executable will also use the directory to create
an output file.  The default name for the output file is output, although a check is performed to see if output already 
exists, of which then it proceeds to check if output (1), output (2), etc are avaliable to be written in.

The encrypted output for the example demonstrated above can be seen as shown.  Sample contained a total of 48 bytes, and
therefore a 48 byte output is produced.

![Output](https://cloud.githubusercontent.com/assets/10404525/10374518/6beb0768-6da8-11e5-8bbb-699c8519d4d9.PNG)

###Results###

Below are a few tests to demonstrate the accuracy of practicalaes for both the EBC and CBC modes.  Consider the following
inputs.  
```
Binary File: 
32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34  
89 A7 D9 8E 98 98 7F 97 36 D9 8C FB 38 23 23 98  
27 66 98 C7 9D 87 76 9D 09 34 8D 86 88 78 D1 10  
Cipher Key:  
2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF F4 3C
Initialization Vector:  
43 F4 3D 32 90 19 3E 4B 92 C9 1A 3D 0F FF 2D 7B
```

```
*ECB Encryption Result*
39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32 
AB 25 81 26 96 E2 AB 09 F3 F5 7F D5 4E 05 A3 04 
05 DF 61 12 9B 8B 48 E3 0C 8C 96 55 14 FB AE 8B
*ECB Decryption Result*
CB 13 38 9C 1D 59 C1 D5 0D 11 F6 B9 0C 38 CE 7F 
B1 FC A2 46 0B A9 2E 01 BB D9 69 D3 6B EA B9 12 
0F 90 D4 CD 97 0F 9B 60 08 1C C7 F6 5A EE B5 12
*CBC Encryption Result*
12 C4 33 FB E1 96 92 54 D6 9B 8E 6C 3E 7B FC 1E 
B3 39 EA 13 3F 47 23 BB C1 3C 8A 12 D4 13 78 77 
A3 CB 72 19 AB 8B EA 7B 82 29 12 87 32 F0 8B 68
*CBC Decryption Result*
9D 3D 2F 05 70 50 FC FD D0 A2 4C D0 56 16 A1 27 
83 74 93 A6 48 F3 1F 36 4D E9 F1 D4 C3 67 1B 26 
86 08 E2 F5 30 97 42 43 D1 63 4B D5 D4 79 4E 8A
```



