/*
 * load_check.c proves a built libmacula loads on this machine and is the ABI
 * macula.h declares: it links the library, asks its ABI version, and makes
 * and frees a cancel token.
 *
 *   cc -I cabi -o load_check scripts/libmacula/load_check.c <library>
 */
#include <stdio.h>

#include "macula.h"

int main(void) {
  int32_t version = macula_abi_version();
  if (version != MACULA_ABI_VERSION) {
    fprintf(stderr, "libmacula is ABI %d, macula.h is ABI %d\n", version, MACULA_ABI_VERSION);
    return 1;
  }
  macula_handle token = macula_cancel_new();
  if (token == 0) {
    fprintf(stderr, "macula_cancel_new returned 0\n");
    return 1;
  }
  macula_cancel(token);
  macula_cancel_free(token);
  printf("libmacula ABI %d loads\n", version);
  return 0;
}
