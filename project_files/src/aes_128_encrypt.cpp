#include "../include/aes_128_encrypt.h"
#include "../include/aes_128_common.h"
#include "../include/aes_128_key_expansion.h"
#include <cstring>

//Encryption functions done by Wholesome100

// Encryption function
byte *encrypt_aes_128(byte *const plaintext, byte *key) {
    byte *ciphertext = new byte[16];
    memcpy(ciphertext, plaintext, 16*sizeof(byte));//Copy memory into allocated ciphertext

    add_round_key(ciphertext, key);//Include round 0, round 0 key is the original key;


    for(unsigned int round=0;round<=8;round++)//AES-128 requires 10 rounds, with the 10th having no mixcolumns
    {

    substitute_bytes(ciphertext);
    shift_rows(ciphertext);
    mix_columns(ciphertext);

    key=get_round_key(key, round);//Get the new roundkey before addition

    add_round_key(ciphertext, key);
    }

    substitute_bytes(ciphertext);//Last round
    shift_rows(ciphertext);
    key=get_round_key(key, 9);

    add_round_key(ciphertext, key);

    return ciphertext;//Return encrypted plaintext
}

// Shift rows
void shift_rows(byte *byte_array) {
    byte temp1, temp2;//Temp values to hold the shift

    //Row2 left cyclical shift
    temp1=byte_array[1];
    byte_array[1]=byte_array[5];
    byte_array[5]=byte_array[9];
    byte_array[9]=byte_array[13];
    byte_array[13]=temp1;

    //Row3 left cyclical shift
    temp1=byte_array[2];
    temp2=byte_array[6];
    byte_array[2]=byte_array[10];
    byte_array[6]=byte_array[14];
    byte_array[10]=temp1;
    byte_array[14]=temp2;

    //Row4 left cyclical shift
    temp1=byte_array[15];
    byte_array[15]=byte_array[11];
    byte_array[11]=byte_array[7];
    byte_array[7]=byte_array[3];
    byte_array[3]=temp1;
}

// Mix Columns
void mix_columns(byte *byte_array) {
    byte hold1, hold2, hold3, hold4, twoByte, threeByte;
    //Maybe have a 0x02*hex function that checks if the value is >FF, and if it is then perform hex XOR 11B

    //Column 1 calculations
    twoByte=checkByte(byte_array[0]);
    threeByte=checkByte(byte_array[1]);
    hold1=(twoByte) ^ (threeByte^byte_array[1])^ byte_array[2] ^ byte_array[3];

    twoByte=checkByte(byte_array[1]);
    threeByte=checkByte(byte_array[2]);
    hold2=byte_array[0] ^ (twoByte) ^ (threeByte^byte_array[2]) ^ byte_array[3];

    twoByte=checkByte(byte_array[2]);
    threeByte=checkByte(byte_array[3]);
    hold3=byte_array[0] ^ byte_array[1] ^ (twoByte) ^ (threeByte ^ byte_array[3]);

    twoByte=checkByte(byte_array[3]);
    threeByte=checkByte(byte_array[0]);
    hold4=(threeByte^byte_array[0]) ^ byte_array[1] ^ byte_array[2] ^ (twoByte);

    //Assign held values to respective rows
    byte_array[0]=hold1;
    byte_array[1]=hold2;
    byte_array[2]=hold3;
    byte_array[3]=hold4;



    //Column 2 calculations
    twoByte=checkByte(byte_array[4]);
    threeByte=checkByte(byte_array[5]);
    hold1=(twoByte) ^ (threeByte^byte_array[5])^ byte_array[6] ^ byte_array[7];

    twoByte=checkByte(byte_array[5]);
    threeByte=checkByte(byte_array[6]);
    hold2=byte_array[4] ^ (twoByte) ^ (threeByte^byte_array[6]) ^ byte_array[7];

    twoByte=checkByte(byte_array[6]);
    threeByte=checkByte(byte_array[7]);
    hold3=byte_array[4] ^ byte_array[5] ^ (twoByte) ^ (threeByte ^ byte_array[7]);

    twoByte=checkByte(byte_array[7]);
    threeByte=checkByte(byte_array[4]);
    hold4=(threeByte^byte_array[4]) ^ byte_array[5] ^ byte_array[6] ^ (twoByte);

    //Assign held values to respective rows
    byte_array[4]=hold1;
    byte_array[5]=hold2;
    byte_array[6]=hold3;
    byte_array[7]=hold4;



    //Column 3 calculations
    twoByte=checkByte(byte_array[8]);
    threeByte=checkByte(byte_array[9]);
    hold1=(twoByte) ^ (threeByte^byte_array[9])^ byte_array[10] ^ byte_array[11];

    twoByte=checkByte(byte_array[9]);
    threeByte=checkByte(byte_array[10]);
    hold2=byte_array[8] ^ (twoByte) ^ (threeByte^byte_array[10]) ^ byte_array[11];

    twoByte=checkByte(byte_array[10]);
    threeByte=checkByte(byte_array[11]);
    hold3=byte_array[8] ^ byte_array[9] ^ (twoByte) ^ (threeByte ^ byte_array[11]);

    twoByte=checkByte(byte_array[11]);
    threeByte=checkByte(byte_array[8]);
    hold4=(threeByte^byte_array[8]) ^ byte_array[9] ^ byte_array[10] ^ (twoByte);

    //Assign held values to respective rows
    byte_array[8]=hold1;
    byte_array[9]=hold2;
    byte_array[10]=hold3;
    byte_array[11]=hold4;



    //Column 4 calculations
    twoByte=checkByte(byte_array[12]);
    threeByte=checkByte(byte_array[13]);
    hold1=(twoByte) ^ (threeByte^byte_array[13])^ byte_array[14] ^ byte_array[15];//Row1

    twoByte=checkByte(byte_array[13]);
    threeByte=checkByte(byte_array[14]);
    hold2=byte_array[12] ^ (twoByte) ^ (threeByte^byte_array[14]) ^ byte_array[15];//Row2

    twoByte=checkByte(byte_array[14]);
    threeByte=checkByte(byte_array[15]);
    hold3=byte_array[12] ^ byte_array[13] ^ (twoByte) ^ (threeByte ^ byte_array[15]);//Row3

    twoByte=checkByte(byte_array[15]);
    threeByte=checkByte(byte_array[12]);
    hold4=(threeByte^byte_array[12]) ^ byte_array[13] ^ byte_array[14] ^ (twoByte);//Row4

    //Assign held values to respective rows
    byte_array[12]=hold1;
    byte_array[13]=hold2;
    byte_array[14]=hold3;
    byte_array[15]=hold4;
}

byte checkByte(byte mult)//checkByte performs x*0x02 and checks if it's over 255
{
    byte prod;
    prod=(0x02*mult);

    if(prod>0xFF)//If prod if over 255, XOR it with 11B
    {
        prod=prod^0x11B;
        return prod;
    }
    else
    {
        return prod;//Otherwise return the product
    }
}

