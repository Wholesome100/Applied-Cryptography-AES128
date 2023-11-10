#include "../include/aes_128_decrypt.h"
#include "../include/aes_128_key_expansion.h"
#include <cstring>

//Decryption functions done by Wholesome100 and Orfield

// Decryption function
byte *decrypt_aes_128(byte *const ciphertext, byte *key) {
    byte *plaintext = new byte[16];
    memcpy(plaintext, ciphertext, 16*sizeof(byte));//State=ciphertext


    byte *r[11];//Initialize an array to hold all the keys
    for(size_t i=0;i<11;i++)
    {
        r[i]=new byte[16];//Elements in r now point to byte arrays
    }


    memcpy(r[0],key, 16*sizeof(byte));//Copy the initial string first


    for(size_t i=0;i<=9;i++)//Go through all roundkeys and put them in the array
    {
    key=get_round_key(key, i);
    memcpy(r[i+1], key, 16*sizeof(byte));
    }

    add_round_key(plaintext, r[10]);//Key schedule is backwards, add keystore[10] first



    for(size_t round=9;round>=1;round--)//Backwards for loop goes through the key schedule backwards, still doing 10 rounds
    {
    inverse_shift_rows(plaintext);
    inverse_substitute_bytes(plaintext);

    add_round_key(plaintext, r[round]);

    inverse_mix_columns(plaintext);
    }

    inverse_shift_rows(plaintext);//Last round
    inverse_substitute_bytes(plaintext);
    add_round_key(plaintext, r[0]);//Add the initial key

    return plaintext;//Return the deciphered text
}

// IS-box ( Inverse substitute a single byte )
byte inverse_substitute_byte(byte byte_to_substitute) {
    byte Inv_sbox[256]={
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    int index = byte_to_substitute;
    return Inv_sbox[index];



    return 0;
}

// Inverse substitute the bytes of the state array
void inverse_substitute_bytes(byte *byte_array)//Changed return type to void
{
     for(unsigned int i=0; i<16;i++ )
    {
        byte_array[i] = inverse_substitute_byte(byte_array[i]);
    }
}

// Inverse Shift rows
void inverse_shift_rows(byte *byte_array) {
    // Fill this function
     byte temp1, temp2;//Temp values to hold the right cyclic shift

    //Row2 shift
    temp1=byte_array[13];
    byte_array[13]=byte_array[9];
    byte_array[9]=byte_array[5];
    byte_array[5]=byte_array[1];
    byte_array[1]=temp1;

    //Row3 shift
    temp1=byte_array[14];
    temp2=byte_array[10];
    byte_array[10]=byte_array[2];
    byte_array[14]=byte_array[6];
    byte_array[6]=temp1;
    byte_array[2]=temp2;

    //Row4 shift
    temp1=byte_array[3];
    byte_array[3]=byte_array[7];
    byte_array[7]=byte_array[11];
    byte_array[11]=byte_array[15];
    byte_array[15]=temp1;
}

// Inverse Mix Columns
void inverse_mix_columns(byte *byte_array) {
    byte hold1, hold2, hold3, hold4, nineByte, elevenByte, thirteenByte, fourteenByte;//Variables to hold calculations

    //Column 1
    nineByte=invCheckByte(byte_array[3], 9);//nineByte is byte*0x09
    elevenByte=invCheckByte(byte_array[1], 11);//elevenByte is byte*0x0B
    thirteenByte=invCheckByte(byte_array[2], 13);//thirteenByte is byte*0x0D
    fourteenByte=invCheckByte(byte_array[0], 14);//fourteenByte is byte*0x0E
    hold1=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 1

    nineByte=invCheckByte(byte_array[0], 9);
    elevenByte=invCheckByte(byte_array[2], 11);
    thirteenByte=invCheckByte(byte_array[3], 13);
    fourteenByte=invCheckByte(byte_array[1], 14);
    hold2=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 2

    nineByte=invCheckByte(byte_array[1], 9);
    elevenByte=invCheckByte(byte_array[3], 11);
    thirteenByte=invCheckByte(byte_array[0], 13);
    fourteenByte=invCheckByte(byte_array[2], 14);
    hold3=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 3

    nineByte=invCheckByte(byte_array[2], 9);
    elevenByte=invCheckByte(byte_array[0], 11);
    thirteenByte=invCheckByte(byte_array[1], 13);
    fourteenByte=invCheckByte(byte_array[3], 14);
    hold4=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 4

    byte_array[0]=hold1;//Assign values to respective rows
    byte_array[1]=hold2;
    byte_array[2]=hold3;
    byte_array[3]=hold4;

    //Column 2
    nineByte=invCheckByte(byte_array[7], 9);
    elevenByte=invCheckByte(byte_array[5], 11);
    thirteenByte=invCheckByte(byte_array[6], 13);
    fourteenByte=invCheckByte(byte_array[4], 14);
    hold1=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 1

    nineByte=invCheckByte(byte_array[4], 9);
    elevenByte=invCheckByte(byte_array[6], 11);
    thirteenByte=invCheckByte(byte_array[7], 13);
    fourteenByte=invCheckByte(byte_array[5], 14);
    hold2=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 2

    nineByte=invCheckByte(byte_array[5], 9);
    elevenByte=invCheckByte(byte_array[7], 11);
    thirteenByte=invCheckByte(byte_array[4], 13);
    fourteenByte=invCheckByte(byte_array[6], 14);
    hold3=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 3

    nineByte=invCheckByte(byte_array[6], 9);
    elevenByte=invCheckByte(byte_array[4], 11);
    thirteenByte=invCheckByte(byte_array[5], 13);
    fourteenByte=invCheckByte(byte_array[7], 14);
    hold4=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 4

    byte_array[4]=hold1;
    byte_array[5]=hold2;
    byte_array[6]=hold3;
    byte_array[7]=hold4;

    //Column 3
    nineByte=invCheckByte(byte_array[11], 9);
    elevenByte=invCheckByte(byte_array[9], 11);
    thirteenByte=invCheckByte(byte_array[10], 13);
    fourteenByte=invCheckByte(byte_array[8], 14);
    hold1=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 1

    nineByte=invCheckByte(byte_array[8], 9);
    elevenByte=invCheckByte(byte_array[10], 11);
    thirteenByte=invCheckByte(byte_array[11], 13);
    fourteenByte=invCheckByte(byte_array[9], 14);
    hold2=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 2

    nineByte=invCheckByte(byte_array[9], 9);
    elevenByte=invCheckByte(byte_array[11], 11);
    thirteenByte=invCheckByte(byte_array[8], 13);
    fourteenByte=invCheckByte(byte_array[10], 14);
    hold3=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 3

    nineByte=invCheckByte(byte_array[10], 9);
    elevenByte=invCheckByte(byte_array[8], 11);
    thirteenByte=invCheckByte(byte_array[9], 13);
    fourteenByte=invCheckByte(byte_array[11], 14);
    hold4=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 4

    byte_array[8]=hold1;
    byte_array[9]=hold2;
    byte_array[10]=hold3;
    byte_array[11]=hold4;


    //Column 4
    nineByte=invCheckByte(byte_array[15], 9);
    elevenByte=invCheckByte(byte_array[13], 11);
    thirteenByte=invCheckByte(byte_array[14], 13);
    fourteenByte=invCheckByte(byte_array[12], 14);
    hold1=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 1

    nineByte=invCheckByte(byte_array[12], 9);
    elevenByte=invCheckByte(byte_array[14], 11);
    thirteenByte=invCheckByte(byte_array[15], 13);
    fourteenByte=invCheckByte(byte_array[13], 14);
    hold2=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 2

    nineByte=invCheckByte(byte_array[13], 9);
    elevenByte=invCheckByte(byte_array[15], 11);
    thirteenByte=invCheckByte(byte_array[12], 13);
    fourteenByte=invCheckByte(byte_array[14], 14);
    hold3=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 3

    nineByte=invCheckByte(byte_array[14], 9);
    elevenByte=invCheckByte(byte_array[12], 11);
    thirteenByte=invCheckByte(byte_array[13], 13);
    fourteenByte=invCheckByte(byte_array[15], 14);
    hold4=fourteenByte^elevenByte^thirteenByte^nineByte;//Row 4

    byte_array[12]=hold1;
    byte_array[13]=hold2;
    byte_array[14]=hold3;
    byte_array[15]=hold4;

}

byte invCheckByte(byte mult, int op)
{
    byte hold1, hold2, prod;//The inverses require repeated multiplication by two, these values hold them

    switch(op)
    {
    case 9://Looks like (((mult*2)*2)*2)^mult, each hold stores the results of a ()*2
    hold1=multiplyBy2(mult);
    hold2=multiplyBy2(hold1);
    prod=multiplyBy2(hold2)^mult;
    return prod;
    break;

    case 11://0x0B multiplication, ((((mult*0x02)*0x02)^mult)*0x02)^mult
    hold1=multiplyBy2(mult);
    hold2=multiplyBy2(hold1)^mult;
    prod=multiplyBy2(hold2)^mult;
    return prod;
    break;

    case 13://0x0D multiplication,
    hold1=multiplyBy2(mult)^mult;
    hold2=multiplyBy2(hold1);
    prod=multiplyBy2(hold2)^mult;
    return prod;
    break;

    case 14://0x0E multiplication
    hold1=multiplyBy2(mult)^mult;
    hold2=multiplyBy2(hold1)^mult;
    prod=multiplyBy2(hold2);
    return prod;
    break;

    default:
    break;
    }

    return 0;
}

byte multiplyBy2(byte mult)//Multiply the byte by 0x02 and XOR with 11B as needed
{
    byte prod;
    prod=mult*0x02;

    if(prod>0xFF)
    {
        prod=prod^0x11B;
        return prod;
    }
    else
    {
        return prod;
    }
}
