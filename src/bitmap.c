#include "bitmap.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// we expect 0 <= n and n < b->bits, but it is not verified

void bitmap_set(bitmap *b, int n)
{
    assert(n >= 0 && n < b->bits);
    int word = n >> bitmap_shift;   // n / bitmap_wordlength
    int position = n & bitmap_mask; // n % bitmap_wordlength
    b->array[word] |= bitmap_one << position;
}

void bitmap_set_consecutive(bitmap *b, uint32_t start_idx, uint32_t slot_len)
{
    assert(start_idx < b->bits);
    assert(start_idx + slot_len <= b->bits);
    for (size_t i = 0; i < slot_len; i++)
    {
        bitmap_set(b, start_idx + i);
    }
}

void bitmap_clear(bitmap *b, int n)
{
    assert(n >= 0 && n < b->bits);
    int word = n >> bitmap_shift;   // n / bitmap_wordlength
    int position = n & bitmap_mask; // n % bitmap_wordlength
    b->array[word] &= ~(bitmap_one << position);
}

void bitmap_clear_consecutive(bitmap *b, uint32_t start_idx, uint32_t slot_len)
{
    assert(start_idx < b->bits);
    assert(start_idx + slot_len <= b->bits);
    for (size_t i = 0; i < slot_len; i++)
    {
        bitmap_clear(b, start_idx + i);
    }
}
int bitmap_read(bitmap *b, int n)
{
    assert(n >= 0 && n < b->bits);
    int word = n >> bitmap_shift;   // n / bitmap_wordlength
    int position = n & bitmap_mask; // n % bitmap_wordlength
    return (b->array[word] >> position) & 1;
}

bitmap *bitmap_allocate(int bits)
{
    assert(bits > 0);
    // error-checking should be better :-)
    bitmap *b = malloc(sizeof(bitmap));
    b->bits = bits;
    b->words = (bits + bitmap_wordlength - 1) / bitmap_wordlength;
    // divide, but round up for the ceiling
    b->array = calloc(b->words, sizeof(bitmap_type));
    return b;
}

void bitmap_deallocate(bitmap *b)
{
    // error-checking should be better :-)
    free(b->array);
    b->array = NULL;
    free(b);
    b = NULL;
}

void bitmap_print_hex(bitmap *b)
{
    for (int i = 0; i < b->words; i++)
    {
        printf(" " bitmap_fmt, b->array[i]);
    }
    printf("\n");
}

void bitmap_print_bit(bitmap *b)
{
    for (size_t i = 0; i < b->bits; i++)
    {
        if (i % 32 == 0)
        {
            printf(" ");
        }
        printf("%d", bitmap_read(b, i));
    }
    printf("\n");
}
