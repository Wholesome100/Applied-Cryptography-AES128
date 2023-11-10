# AES-128 Applied Cryptography

This was a university project for Applied Cryptography back in Spring 2021.
In it, we implemented the AES cipher for 128-bit keys.


# Running the Code

Clone the repository into Visual Studio 2022 or higher. The main file contains a sample case with a pre-inserted plaintext and a key 16 characters in length.
Run the local windows debugger, and the program will execute.
The key and plaintext are converted into arrays of hex bytes (read column major) before being encrypted into the ciphertext.
Le ciphertext is then decrypted using the key, and will match the initial state of the plaintext.
