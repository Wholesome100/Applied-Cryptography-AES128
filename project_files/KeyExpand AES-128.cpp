#include <iostream>
#include "include/aes_128_common.h"
#include "include/aes_128_encrypt.h"
#include "include/aes_128_key_expansion.h"
#include "include/aes_128_decrypt.h"

using namespace std;

int main() {
    byte *key = string_to_byte_array("FLORIDAPOLYUNIV");

    cout<<"Roundkey 0:";
    print_byte_array(key,16);


    for(int i=0;i<9;i++)
    {
    newline();
    key=get_round_key(key, i);
    cout<<"Roundkey "<<i+1<<":";
    print_byte_array(key, 16);
    }

    newline();//Round 10 kept being printed as Roundkey a: in the loop, placed it here for simplicity
    key=get_round_key(key, 9);
    cout<<"Roundkey 10:";
    print_byte_array(key, 16);

    delete key;
    return 0;
}
