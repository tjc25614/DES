// Author: Tom Conroy

#include "des.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char const *argv[])
{
    int do_encrypt = 1;
    uint64_t in_text, key, out_text;
    // make sure the number of expected arguments are present
    if(argc < 3 || argc > 4)
    {
        printf("Usage: %s [-d] TEXT KEY (both in hexadecimal)\n", argv[0]);
        return 1;
    }
    else if(argc == 4)
    {
        if(strcmp(argv[1], "-d") == 0)
        {
            do_encrypt = 0;
            in_text = strtoull(argv[2], NULL, 16);
            key = strtoull(argv[3], NULL, 16);
        }
        else
        {
            printf("Usage: %s [-d] TEXT KEY (both in hexadecimal)\n", argv[0]);
            return 1;
        }
    }
    else
    {
        in_text = strtoull(argv[1], NULL, 16);
        key = strtoull(argv[2], NULL, 16);
    }

    printf("Input:  %016lx\n", in_text);
    printf("Key:    %016lx\n", key);

    if(do_encrypt)
    {
        printf("Doing DES encryption...\n");
        out_text = des_encrypt(in_text, key);
    }
    else
    {
        printf("Doing DES decryption...\n");
        out_text = des_decrypt(in_text, key);
    }
    printf("Output: %016lx\n", out_text);

    return 0;
}
