#include <iostream>

#ifndef AES_128_COMMON_H
#define AES_128_COMMON_H

typedef unsigned int byte;

byte *string_to_byte_array(std::string str);

void print_byte_array(byte *byte_array, size_t length);

void print_state(byte *byte_array);

void newline();

void add_round_key(byte *byte_array, byte *key);

byte substitute_byte(byte byte_to_substitute);

void substitute_bytes(byte *byte_array);

#endif //AES_128_COMMON_H
