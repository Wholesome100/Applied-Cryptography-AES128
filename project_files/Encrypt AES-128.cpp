#include <iostream>
#include "include/aes_128_encrypt.h"

using namespace std;

int main() {
    byte *key = string_to_byte_array("FLORIDAPOLYUNIV");
    byte *plaintext_block = string_to_byte_array("AES-128 is great!");//Build properties

    byte *ciphertext=NULL;


    newline();
    cout << "Key:\n";
    print_byte_array(key, 16);

    newline();
    cout<<"Initial state:\n";
    print_state(plaintext_block);


    newline();
    ciphertext=encrypt_aes_128(plaintext_block, key);
    cout<<"Ciphertext:\n";
    print_state(ciphertext);


    delete key;
    delete plaintext_block;
    delete ciphertext;

    return 0;
}
