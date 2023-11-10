#include "aes_128_common.h"

#ifndef AES_128_KEY_EXPANSION_H
#define AES_128_KEY_EXPANSION_H

void circular_left_shift(byte *byte_word);

void add_round_constant(byte *byte_word);

byte *g_function(byte *byte_word);

byte *get_round_key(byte *key_bytes, unsigned char round_number);

#endif //AES_128_KEY_EXPANSION_H
