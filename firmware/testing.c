#include "../bootloader/lib/tinycrypt/lib/include/tinycrypt/aes.h"
#include "../bootloader/lib/tinycrypt/lib/include/tinycrypt/cbc_mode.h"
#include "stdio.h"

void main(void)
{
    FILE * encrypted_file = fopen("test_fw.prot","r");
    FILE * key_file = fopen("test_key", "r");
    FILE * iv_file = fopen("test_iv", "r");
    FILE * decrypted_file = fopen("test_fw.dec", "w+");
    unsigned int len = 1376;
    unsigned char inbuf[len], outbuf[len];
    uint8_t key[32], iv[32];
    fread(key, sizeof(uint8_t), 32, key_file);
    fread(iv, sizeof(uint8_t), 32, iv_file);
    fread(inbuf, sizeof(unsigned char), len, encrypted_file);
    struct tc_aes_key_sched_struct sched;
    tc_aes128_set_decrypt_key(&sched, key);
    tc_cbc_mode_decrypt(outbuf, len, inbuf, len, iv, &sched);
    fwrite(outbuf, sizeof(unsigned char), len, decrypted_file);
}