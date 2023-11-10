#include "../include/aes_128_key_expansion.h"
#include <cstring>

//Key expansion functions done by Wholesome100

// Circular Left Shift (Rotate Left)
void circular_left_shift(byte *byte_word) {
    byte temp=byte_word[0];

    byte_word[0]=byte_word[1];
    byte_word[1]=byte_word[2];
    byte_word[2]=byte_word[3];
    byte_word[3]=temp;
}

// Add Round Constant
void add_round_constant(byte *byte_word, unsigned char round_number) {
    int index=round_number;
    byte roundC[10]={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};//Array with all subwords for each round
    byte holdC=roundC[index];

    byte_word[0]=byte_word[0]^holdC;//Addition of the roundkey at index
    byte_word[1]=byte_word[1]^0x00;
    byte_word[2]=byte_word[2]^0x00;
    byte_word[3]=byte_word[3]^0x00;
}


// The g function of the AES key expansion
byte *g_function(byte *const byte_word, unsigned char round_number)//Had to edit the header so it takes the round_number as well
{
    byte *g_return_word=new byte[4];
    memcpy(g_return_word, byte_word, 4*sizeof(byte));//Copy word3 into g_return_word

    circular_left_shift(g_return_word);//Shift the return word

    for(int i=0;i<4;i++)//For loop substitutes the byte in the passed word
    {
        g_return_word[i]=substitute_byte(g_return_word[i]);
    }

    add_round_constant(g_return_word, round_number);//Add the round constant

    return g_return_word;
}


// Get round key
byte *get_round_key(byte *key_bytes, unsigned char round_number) {
    byte *round_key = new byte[16];//Declare arrays for the round_key and g function return
    byte *gbyte= new byte[4];

    byte word0[4]={key_bytes[0],key_bytes[1],key_bytes[2],key_bytes[3]};//Assign values into each word
    byte word1[4]={key_bytes[4],key_bytes[5],key_bytes[6],key_bytes[7]};
    byte word2[4]={key_bytes[8],key_bytes[9],key_bytes[10],key_bytes[11]};
    byte word3[4]={key_bytes[12],key_bytes[13],key_bytes[14],key_bytes[15]};

    byte rk0[4], rk1[4], rk2[4], rk3[4];//Words to hold the new words of the key schedule

    gbyte=g_function(word3, round_number);//Pass word3 to the g function and set gybte= to the return

    for(int i=0;i<4;i++)//For loop does the next word generation byte by byte
    {
        rk0[i]=gbyte[i]^word0[i];
        rk1[i]=rk0[i]^word1[i];
        rk2[i]=rk1[i]^word2[i];
        rk3[i]=rk2[i]^word3[i];
    }


    for(int i=0;i<4;i++)//For loop to place all word bytes into round_key
    {
        round_key[i]=rk0[i];
        round_key[i+4]=rk1[i];
        round_key[i+8]=rk2[i];
        round_key[i+12]=rk3[i];
    }


    delete gbyte;//Free the gbyte and return the roundkey
    return round_key;
}

