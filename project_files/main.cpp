#include <iostream>
#include "include/aes_128_common.h"
#include "include/aes_128_encrypt.h"
#include "include/aes_128_key_expansion.h"
#include "include/aes_128_decrypt.h"

using namespace std;

int main() {

    /**********************************************************
     * The content of this function can be completely replaced
     **********************************************************/
    //byte *key = string_to_byte_array("FLORIDAPOLYUNIV");
    //byte *plaintext_block = string_to_byte_array("AES-128 is great!");//Build properties

    byte *key = string_to_byte_array("Thats my Kung Fu");
    //byte *plaintext_block = string_to_byte_array("Two One Nine Two");

    //byte hold1[16]={0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    //byte hold2[16]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

    byte hold1[16]={0x29, 0xc3, 0x50, 0x5f, 0x57, 0x14, 0x20, 0xf6, 0x40 ,0x22, 0x99, 0xb3, 0x1a,0x02,0xd7,0x3a};

     byte *plaintext_block=hold1;
    //byte *key=hold2;



    byte *ciphertext=NULL;
    byte *plaintext=NULL;

    /*byte test=0xc3;
    cout<<"Value of test before:"<<test<<"\n";
    test=invCheckByte(0xc3, 9);
    cout<<"Value of test after:"<<test<<"\n";*/


    //byte hold[16]={0x2b, 0x7e ,0x15, 0x16 ,0x28 ,0xae, 0xd2 ,0xa6 ,0xab ,0xf7 ,0x15 ,0x88 ,0x09 ,0xcf ,0x4f ,0x3c};
    //byte *key=hold;

    newline();
    cout << "Key: ";
    print_byte_array(key, 16);
   // newline();
    //print_state(plaintext_block);

    newline();
    cout<<"Initial state:\n";
    print_state(plaintext_block);
/*
    newline();
    add_round_key(plaintext_block, key);
    cout<<"After AddRoundKey:\n";
    print_state(plaintext_block);

    newline();
    substitute_bytes(plaintext_block);
    cout<<"After SubBytes:\n";
    print_state(plaintext_block);

    newline();
    shift_rows(plaintext_block);
     cout<<"After ShiftRows:\n";
    print_state(plaintext_block);

    newline();
    mix_columns(plaintext_block);
    //cout << "Plaintext block:" << endl;
    cout<<"After MixColumns:\n";
    print_state(plaintext_block);
    */

    /*newline();
    key=get_round_key(key, 1);
    cout<<"First roundkey:";
    print_byte_array(key, 16);

    newline();
    key=get_round_key(key, 2);
    cout<<"Second roundkey:";
    print_byte_array(key, 16);*/



    /*for(int i=0;i<=9;i++)
    {
    newline();
    key=get_round_key(key, i);
    cout<<"Roundkey "<<i+1<<":";
    print_byte_array(key, 16);
    }*/

    /*newline();
    add_round_key(plaintext_block, key);
    print_state(plaintext_block);

    newline();
    inverse_substitute_bytes(plaintext_block);
    print_state(plaintext_block);

    newline();
    inverse_shift_rows(plaintext_block);
    print_state(plaintext_block);

    newline();
    inverse_mix_columns(plaintext_block);
    print_state(plaintext_block);*/

    /*newline();
    ciphertext=encrypt_aes_128(plaintext_block, key);
    //inverse_shift_rows(plaintext_block);
    cout<<"Encrypted plaintext:\n";
    print_state(ciphertext);*/


    newline();
    plaintext=decrypt_aes_128(plaintext_block, key);
    //ciphertext=encrypt_aes_128(plaintext_block, key);
    cout<<"Decrypted ciphertext:\n";
    print_state(plaintext);



    delete key;
    delete plaintext_block;

    return 0;
}
