// tests/fixtures/test_dataflow.c
// Purpose-built for ReVa dataflow tests: a clear producer -> transform -> consumer
// chain so trace-data-flow-forward/backward and find-variable-accesses have real
// def/use edges to report.
// Compile (Mach-O x86_64 to match the other fixtures):
//   clang -O0 -fno-inline -arch x86_64 -o test_dataflow_x86_64 test_dataflow.c
#include <stdio.h>
int transform(int seed) {
    int a = seed + 7;
    int b = a * 3;
    int c = b - a;
    return c;
}
int main(void) {
    int r = transform(11);
    printf("%d\n", r);
    return 0;
}
