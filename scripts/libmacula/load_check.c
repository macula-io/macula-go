/*
 * load_check.c proves a built libmacula loads on this machine and is the ABI
 * macula.h declares: it links the library, asks its ABI version and the
 * release it was built from, and makes and frees a cancel token.
 *
 *   cc -I cabi -o load_check scripts/libmacula/load_check.c <library>
 *   ./load_check [expected-release]
 *
 * With an expected release (the tag, on a release build; "devel", on a build
 * that is not one) the release the library reports must equal it: a released
 * library must never say "devel", nor claim a release it is not.
 */
#include <stdio.h>
#include <string.h>

#include "macula.h"

int main(int argc, char **argv) {
  if (argc > 2) {
    fprintf(stderr, "usage: load_check [expected-release]\n");
    return 2;
  }
  int32_t version = macula_abi_version();
  if (version != MACULA_ABI_VERSION) {
    fprintf(stderr, "libmacula is ABI %d, macula.h is ABI %d\n", version, MACULA_ABI_VERSION);
    return 1;
  }
  const char *release = macula_library_version();
  if (argc == 2 && strcmp(release, argv[1]) != 0) {
    fprintf(stderr, "libmacula says it is built from %s, expected %s\n", release, argv[1]);
    return 1;
  }
  macula_handle token = macula_cancel_new();
  if (token == 0) {
    fprintf(stderr, "macula_cancel_new returned 0\n");
    return 1;
  }
  macula_cancel(token);
  macula_cancel_free(token);
  printf("libmacula %s loads (ABI %d)\n", release, version);
  return 0;
}
