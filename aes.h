#ifndef KEY_SCHEDULE_H
#define KEY_SCHEDULE_H

#include <stdint.h>
#include <stddef.h>

uint32_t convert_to_uint32(uint8_t arr[4]);
void convert_to_uint8_array(uint32_t w,uint8_t arr[4]);
uint32_t rot_word(uint32_t w);
uint32_t sub_word(uint32_t w);
uint32_t rcon(uint8_t round, uint32_t w);
void expand_key(uint8_t round, uint8_t *key);
void add_round_key(uint8_t *state, uint8_t *key, size_t block_size);
void sub_bytes(uint8_t *state, size_t block_size);
void inv_sub_bytes(uint8_t *state, size_t block_size);
void shift_rows(uint8_t *state, size_t block_size);
void inv_shift_rows(uint8_t *state, size_t block_size );
void mix_columns(uint8_t *state);
void inv_mix_columns(uint8_t *state);
void aes_enc(uint8_t *text,uint8_t *key);
void aes_dec(uint8_t *text,uint8_t *key);
uint8_t mul(uint8_t coefficient, uint8_t val) ;
void aes_cbc_enc(uint8_t *text, uint8_t *key, uint8_t *iv);
void print_block(uint8_t block[16]);

#endif
