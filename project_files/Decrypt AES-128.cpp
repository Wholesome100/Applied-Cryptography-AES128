#include <iostream>
#include "include/aes_128_common.h"
#include "include/aes_128_encrypt.h"
#include "include/aes_128_key_expansion.h"
#include "include/aes_128_decrypt.h"

using namespace std;

int main() {

    byte *key = string_to_byte_array("FLORIDAPOLYUNIV");
    byte ciphertext[16]={0x2a,0x12,0xc3,0xae,0x6e,0x82,0x0a,0x27,0x13,0x04,0x80,0x46,0xf4,0x92,0xba,0x75};

    byte *ciphertext_block = ciphertext;

    byte *plaintext=NULL;


    newline();
    cout << "Key:\n";
    print_byte_array(key, 16);

    newline();
    cout<<"Initial state:\n";
    print_state(ciphertext_block);

    newline();
    plaintext=decrypt_aes_128(ciphertext_block, key);
    cout<<"Plaintext:\n";
    print_state(plaintext);



    delete key;
    delete ciphertext_block;
    delete plaintext;

    return 0;
}
