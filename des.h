#ifndef _DES_H
#define _DES_H

#include <stdint.h>

uint64_t des_encrypt(uint64_t plaintext, uint64_t key);
uint64_t des_decrypt(uint64_t ciphertext, uint64_t key);

#endif
