This file contains the logic behind PracticalAES's search algorithm to retrieve files of a given extension.  Note that this 
is fairly tentative and is additionally used to clarify as well as help improve the code.

The concept behind file retrieval is to retireve individual files without completely saving every file that is decrypted.
For example, let's say I have a .doc file that is encrypted and has the directory "./folder1/folder2/text.doc".  The folder in
which my executable is located for this purpose will be listed as "C:/Users/Andrew/cworkspace/PracticalAES/".  If I were to
retrieve the encrypted doc file, I would want to combine concatenate the two directories and have the .doc file decrypted.

However, the biggest issue behind this is doing this efficiently.  There are two main problems behind retrieving files.  The
first is relative to how AES by perates.  AES decryption/encryption operates on 16 bytes at a time.  Therefore, it is
possible to have file names split across multiple instances of 16 bytes. The second issue is that there is a lot of uncertainty
by looking at single byte alone.  Assuming that I only want to look at a set of 16 bytes at any given instance, it is important
to be able to accurately determine where file starts, ends, and where the extension is located.  Combined with the fact that
a set of files can be encrypted in almost any given number of ways, it is important that the algorithm is flexible enough to 
handle a variety of cases.

The way this solution is approached is to assume that at any given time, there are 3 possible states, as well as several 
possible cases at each given state.

*State 1: The algorithm is currently looking for the start of the directory.*    
This is usually identified by the combination of the two consecutive characters './', which indicate that from the current 
folder, there exists a subfolder.  During this period, there are several possible cases as listed below.
```
Case 1: '.' is found, check for '/' on the next line set new line, index 0, go to State 2

Case 2: './' exist on the same line, found '.', check for '/' next check next index, if not, do nothing and 
increment index.  If there is a match, then proceed to State 2.

Case 3: The character '.' triggers a false alarm and is just listed by itself, increment index.  Continue at State 1
```

*State 2: The start of a directory is found, and now the file extension is compared to see if a match exists to user input.*
At this point, there are multiple cases that may occur.  The obvious ones are that the extention either matches, or it 
doesn't, but there is also a character count in place to prevent buffer overflows in the case that the file name is 
intentionally designed to cause one.
```
Case 1: Continue searching for file extension and buffer count is hit.  Set index at next and go back to State 1.

Case 2: A file extension match is found to what the user requests.  Set index at next and proceed to State 3.

Case 3: A file extension is found but does not match user request.  Set index at next and proceed to State 1.
```

*State 3: A directory with an extension that matches the user request is found.*
Once a match is found to what the user wants, the directory is created if it doesn't exist.  Furthermore, the contents of 
the file are written into the absolute directory until the algorithm can safetly determine that the folder has no more
contents that need to be written into it.
```
Case 1: Continue writing into the folder and traverse new lines as needed.  Remains at State 3.

Case 2: A new folder directory is found, which indicates the end of writing to the file.  Proceed to State 1, retain index.
```


