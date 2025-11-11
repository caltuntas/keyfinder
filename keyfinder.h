#ifndef KEYFINDER_H
#define KEYFINDER_H

#define BUFFER_SIZE 4096

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

bool check_aes_128_key_expantion(uint8_t *buf,size_t s);

#endif
