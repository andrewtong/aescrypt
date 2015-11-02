#Practical AES#

PracticalAES currently fully supports EBC and CBC decryption.  A secondary search function that can retrieves decrypted files
based off their file extention (e.x. '.doc', '.sql', '.txt') is currently being implemented.

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
>File Retrieval (CBC, IV provided): practicalaes.exe s cipherkey binaryfile .ext iv  
>File Retrieval (CBC, IV assumed to be first 16 bytes): practicalaes.exe s cipherkey binaryfile .ext

Encrypting/Decrypting binary files is fairly straightforward, where the cipher key, binary file to be encrypted/decrypted, as
well as the initialization vector (if CBC is being used) are written in binary files.  For file retrieval, CBC mode is 
the only mode supported and comes with the option of either providing a supplementary argument that provides the iv key
via 16 bytes, or can be performed with an supplementary iv key file, in which it is assumed that the first 16 bytes within
the binary code that is to be decrypted is the initialization vector.

The simplest way create and edit binary files using hex values is via a hex editor.  An example is shown in the image below.

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
The resulting outputs for various encryption/decryption scenarios are displayed below.
```
ECB Encryption Result
D9 0D A0 3F BD BD 20 71 E9 37 DB 6E 42 1D D3 62 
6B D9 79 1A 7E 9B 58 A4 84 07 C4 47 12 A5 68 FF  
1C CA 74 05 F5 1B 9E 5B 6B 4E 4C 25 FF 29 89 BD  
ECB Decryption Result
64 F8 C9 20 98 E2 B2 54 E6 09 D2 66 6B CB FD 9A  
41 E1 63 B1 09 C6 F4 B8 B7 43 4B 25 31 18 30 A8  
B0 F7 86 89 B7 18 FB 04 6A CE 04 F3 EF B8 63 7E  
CBC Encryption Result
E8 DE C5 0E 7A D0 26 A8 2C 0D 25 0F 4A 18 C3 BF  
EF 2E 2B 5A 1B 65 07 FA 12 A4 23 67 BA 88 F6 48  
85 86 40 1B B3 4B 8E 56 8B D4 8E 33 E6 95 75 EE  
CBC Decryption Result
27 0C F4 12 08 FB 8C 1F 74 C0 C8 5B 64 34 D0 E1  
73 A2 95 19 81 9C C4 35 86 72 D3 87 D1 2F 37 9C  
39 50 5F 07 2F 80 84 93 5C 17 88 08 D7 9B 40 E6  
```

###File Retrieval###

This section demonstrates usage of the file retrieval option for practicalAES.  The following values are encrypted using the
CBC option using the cipher key and initialization vector provided below.
```
Binary File: 
2E 2F 66 6F 6C 64 65 72 31 2F 66 6F 6C 64 65 72  
32 2F 73 61 6D 70 6C 65 2E 62 69 6E 68 65 6C 6C  
6F 77 6F 72 6C 64 00 00 00 00 00 00 00 00 00 00   
Cipher Key:  
2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF F4 3C
Initialization Vector:  
43 F4 3D 32 90 19 3E 4B 92 C9 1A 3D 0F FF 2D 7B
```

The binary file points to a directory with a .bin extension, and the contents of the file are written afterwards, as shown
in the image below.

![searchsampleimage](https://cloud.githubusercontent.com/assets/10404525/10872614/feb61536-80ba-11e5-8c0e-c43b862ce1da.PNG)

Once encrypted, the search function of practicalAES is used, combined with the given cipher key and initialization vector
to search for files with a .bin extension.  The directory will then be created if it doesn't exist, and the contents of the
file will be written out.

![commandlinesearchimage](https://cloud.githubusercontent.com/assets/10404525/10872616/03c1de0c-80bb-11e5-8a6b-ceb9243005e1.PNG)

In the above photo, I CBC encrypt the searchsample file and by default, the encrypted text is stored in a file named output.
I am able to immediately use this file via the search option to retrieve the contents of the .bin file as demonstrated
below.

![resultimage](https://cloud.githubusercontent.com/assets/10404525/10872615/01e37e42-80bb-11e5-8c37-d0ad217d36b2.PNG)



