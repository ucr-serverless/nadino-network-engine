#ifndef BITMAP_H_
#define BITMAP_H_


#include <stdint.h>
#include <assert.h>
#define bitmap_type uint32_t

#define bitmap_shift        5
#define bitmap_mask        31
#define bitmap_wordlength  32
#define bitmap_fmt "%08x"
// get the types right
#define bitmap_one        (bitmap_type)1

typedef struct {
  int bits;	// number of bits in the array
  int words;	// number of words in the array
  bitmap_type *array;
} bitmap;

void bitmap_set_consecutive(bitmap *b, uint32_t start_idx, uint32_t slot_len);
void bitmap_clear_consecutive(bitmap *b, uint32_t start_idx, uint32_t slot_len);
void bitmap_set  (bitmap *b, int n);	// n is a bit index
void bitmap_clear(bitmap *b, int n);
int  bitmap_read (bitmap *b, int n);

bitmap * bitmap_allocate(int bits);
void bitmap_deallocate(bitmap *b);

void bitmap_print_hex(bitmap *b);
void bitmap_print_bit(bitmap *b);
#endif // !BITMAP_H_
