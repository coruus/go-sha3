#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "print-impl.h"

#define N 31
#define REPS 65536
#define cycles __builtin_readcyclecounter

void bench(void) {
  uint8_t s1[200] = {0};
  uint8_t s2[200] = {0};
  uint8_t dst[200] = {0};
  double meancpb = 0;
  for (uint64_t n = 1; n < 97; n++) {
    uint64_t start = cycles();
    for (uint64_t r = 0; r < REPS; r++) {
      xorinto_gpr(dst, s1, s2, n);
    }
    double cpb = cycles() - start;
    cpb /= (REPS * n);
    printf("%3llu, %5.2f  ", n, cpb);
    if (((n) % 8) == 0) {
      printf("\n");
    }
  }
}




int main(void) {
  uint8_t s1[N];
  uint8_t s2[N];
  uint8_t dst[N];

  for (int i = 0; i < N; i++) {
    s1[i] = 67 * i;
    s2[i] = i;
  }
 // printbuf(s1, N);
 // printbuf(s2, N);
  xorinto_gpr(dst, s1, s2, N);
 // printbuf(dst, N);
  for (int i = 0; i < N; i++) {
    if ((s1[i] ^ s2[i]) != dst[i]) {
      printf("\ni=%u, %02x, %02x, %02x\n", i, s1[i], s2[i], dst[i]);
  }}
  bench();
}
