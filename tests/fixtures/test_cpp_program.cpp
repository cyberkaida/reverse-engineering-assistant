// Test C++ program for ReVa vtable tests.
//
// Builds two distinct vtables (Dog, Cat) deriving from one abstract base
// (Animal), plus an indirect call site through a base pointer that exercises
// find-vtable-callers / find-vtables-containing-function.
//
// Compile (Mach-O ARM64):
//   clang++ -O0 -arch arm64 -std=c++17 -fno-inline -fno-rtti=0 \
//           -o test_cpp_arm64 test_cpp_program.cpp
//
// Notes:
//   * -O0 + -fno-inline keeps vtable dispatch visible at the asm level.
//   * RTTI left enabled (default) so Ghidra's RTTI analyzer can find
//     `typeinfo for Animal` / `vtable for Animal` style symbols.
//   * No <stdio.h>/printf — we don't care what it does at runtime, only
//     that it compiles to a binary with discoverable vtables.

class Animal {
public:
    virtual ~Animal() {}
    virtual int legs() const = 0;
    virtual int speak() const { return 0; }
};

class Dog : public Animal {
public:
    int legs() const override { return 4; }
    int speak() const override { return 1; }
};

class Cat : public Animal {
public:
    int legs() const override { return 4; }
    int speak() const override { return 2; }
};

int dispatch(const Animal* a) {
    // Indirect call through the base pointer — this is the site we expect
    // find-vtable-callers to surface.
    return a->legs() + a->speak();
}

int main() {
    Dog d;
    Cat c;
    int total = 0;
    total += dispatch(&d);
    total += dispatch(&c);
    return total;
}
