/*
 * Simple test program for ReVa import testing.
 * Compiled as a fat Mach-O binary (x86_64 + arm64) for testing slice extraction.
 */
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}

int main(int argc, char *argv[]) {
    printf("ReVa Test Program\n");
    printf("2 + 3 = %d\n", add(2, 3));
    printf("4 * 5 = %d\n", multiply(4, 5));
    return 0;
}
