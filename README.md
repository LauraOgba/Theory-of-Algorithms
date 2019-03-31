# Theory-of-Algorithms

### Student Name: Laura Ogba


## Introduction to SHA256 

This Standard specifies secure hash algorithms, SHA-256. This algorithms is iterative, one-way hash
functions that can process a message to produce a condensed representation called a message
digest. This algorithms enables the determination of a message’s integrity: any change to the
message will, with a very high probability, result in a different message digest. This property is
useful in the generation and verification of digital signatures and message authentication codes,
and in the generation of random numbers or bits. 

## What is SHA256 used for?

This algorithm can be described in two stages: preprocessing and hash computation.
Preprocessing involves padding a message, parsing the padded message into m-bit blocks, and
setting initialization values to be used in the hash computation. The hash computation generates
a message schedule from the padded message and uses that schedule, along with functions,
constants, and word operations to iteratively generate a series of hash values. The final hash
value generated by the hash computation is used to determine the message digest. 
 
## How the files in the program work

**SHA256**

SHA-256 uses six logical functions, where each function operates on 32-bit
words, which are represented as x, y, and z. The result of each function is a new 32-bit word. 


**Constants**

 SHA-256 uses the same sequence of sixty-four constant 32-bit words,
{256} {256} {256} K ,K ,…,K . These words represent the first thirty-two bits of the fractional parts of 0 1 63
the cube roots of the first sixty-four prime numbers. In hex, these constant words are (from left
to right)

**Procesing and Padding the message**

Preprocessing consists of three steps: padding the message, M (Sec. 5.1), parsing the message
into message blocks (Sec. 5.2), and setting the initial hash value, H(0) (Sec. 5.3). The purpose of this padding is to ensure that the padded message is a multiple of 512 or 1024
bits, depending on the algorithm. Padding can be inserted before hash computation begins on a
message, or at any other time during the hash computation prior to processing the block(s) that
will contain the padding. 

**Changing characters from BIG ENDIAN to small endian

In order to change these characters from big to small endian, using macros.These macros provide a portable way to determine the host byte order and to convert values between different byte orders.
The byte order is the order in which bytes are stored to create larger data types such as the gint and glong values. The host byte order is the byte order used on the current machine.



## How to run the program

* Step 1: Git clone or download this repository or into your google cloud(virtual machine)
* Step 2: To get a google cloud VM follow this: https://cloud.google.com/compute/docs/quickstart-linux

**Testing the program:**

* Step 3: To complie the sha file use "gcc -o sha256 sha256.c". This will compile to ensure there are no pending errors.
* Step 4: To compile the pad file use "gcc -o padfile padfile.c", to also ensure that there are no pending errors.

**Testing for result:**

* Step 5: To run the sha file itself: ./sha256 sha256 and ./sha256 sha256.c
  **Result should be as below**
  
* Step 6: To run the padfile: ./sha256 padfile and ./sha256 padfile.c
  **Result should be as below**
  
 * Step 7: To run the first test file : ./sha256 test1.txt
  **Result should be as below**
  
 * Step 8: To run the second test file : ./sha256 Test2.txt
  **Result should be as below** 
 


## References:
1- SHA-256 Part 1: https://web.microsoftstream.com/video/db7c03be-5902-4575-9629-34d176ff1366

2- SHA-256 Part 2: https://web.microsoftstream.com/video/2a86a2ac-aafb-46e0-a278-a3faa1d13cbf

3- Unions in C: https://web.microsoftstream.com/video/78dc0c8d-a017-48c8-99da-0714866f35cb

4- Padding for SHA256: https://web.microsoftstream.com/video/9daaf80b-9c4c-4fdc-9ef6-159e0e4ccc13

5- SHA256: Finishing out the padding: https://web.microsoftstream.com/video/200e71ec-1dc1-47a4-9de8-6f58781e3f38

6- Finishing out the SHA256 algorithm: https://web.microsoftstream.com/video/f823809a-d8df-4e12-b243-e1f8ed76b93f

7- FEDERAL INFORMATION PROCESSING STANDARDS PUBLICATION https://ws680.nist.gov/publication/get_pdf.cfm?pub_id=910977

8- Macros: https://people.gnome.org/~desrt/glib-docs/glib-Byte-Order-Macros.html

9- Converting the Endian:http://www.firmcodes.com/write-c-program-convert-little-endian-big-endian-integer/

10. Reading a text file: https://www.quora.com/How-do-I-check-file-is-empty-in-c-file-handling-I-am-trying-to-write-a-variable-in-file-like-m-0-when-file-is-empty and http://www.runoob.com/cprogramming/c-function-fread.html
  
