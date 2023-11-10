#include <iostream>
#include "include/aes_128_common.h"
#include "include/aes_128_encrypt.h"
#include "include/aes_128_key_expansion.h"
#include "include/aes_128_decrypt.h"

using namespace std;

int main() {
    byte *key = string_to_byte_array("Thats my Kung Fu");
    byte *plaintext_block = string_to_byte_array("Two One Nine Two");

    byte *ciphertext=NULL;
    byte *plaintext=NULL;

    newline();
    cout << "Key: ";
    print_byte_array(key, 16);

    newline();
    cout<<"Initial state:\n";
    print_state(plaintext_block);

    newline();
    ciphertext=encrypt_aes_128(plaintext_block, key);
    cout<<"Encrypted plaintext:\n";
    print_state(ciphertext);

    newline();
    plaintext = decrypt_aes_128(ciphertext, key);
    cout << "Decrypted ciphertext:\n";  
    print_state(plaintext);
    

    delete key;
    delete plaintext_block;

    return 0;
}
