#ifndef KEYFINDER_H
#define KEYFINDER_H

#define BUFFER_SIZE 4096

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
	bool found;
	unsigned int offset;
} key_search_result_t;

key_search_result_t check_aes_128_key_expantion(uint8_t *buf,size_t s);

#endif
