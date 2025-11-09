# CTF Binary Exploitation Patterns

This document contains patterns for recognizing common vulnerability classes and exploitation primitives in CTF challenges. Focus on **conceptual understanding** rather than specific exploits.

## Vulnerability Recognition Patterns

### Unsafe String Operation Patterns

**Conceptual characteristics**:
- Functions that don't check destination buffer size
- Unbounded copying from source to destination
- Reliance on null terminator without size validation
- No length parameter or ignored length parameter

**Dangerous API patterns**:

```c
// Unbounded copy (no size checking)
strcpy(dest, user_input);           // Copies until null byte
strcat(dest, user_input);           // Appends until null byte
sprintf(dest, "%s", user_input);    // Formats without bounds
gets(buffer);                       // Reads unlimited from stdin

// Underspecified bounds
strncpy(dest, src, sizeof(dest));   // Doesn't guarantee null termination
scanf("%s", buffer);                // No size limit specified
read(fd, buffer, 1024);             // May exceed buffer size if buffer < 1024
recv(sock, buffer, MAX, 0);         // May exceed buffer capacity
```

**What to look for in decompiled code**:
```
Buffer declaration:
  char buffer[64];                  // Fixed-size local array

Unsafe operation on same buffer:
  strcpy(buffer, user_input);       // No size check
  read(fd, buffer, 256);            // Reads more than buffer holds

Distance to critical data:
  buffer[64]                        // Local variable at stack offset
  saved_rbp                         // Usually at buffer + buffer_size
  return_address                    // Usually at buffer + buffer_size + 8
```

**Investigation strategy**:
1. `get-symbols` includeExternal=true → Find strcpy, strcat, gets, scanf, sprintf imports
2. `find-cross-references` to unsafe functions → Locate call sites
3. `get-decompilation` with includeContext=true → Analyze buffer size vs. input size
4. Calculate: input_max_size > buffer_size? → Buffer overflow exists
5. `set-bookmark` type="Warning" category="Buffer Overflow" at vulnerability

**Telltale signs**:
- Local char arrays with small sizes (64, 128, 256 bytes)
- Unbounded string functions called on those arrays
- User input directly passed to unsafe function
- No explicit size checking before copy operation

### Format String Vulnerability Patterns

**Conceptual characteristics**:
- User controls the format string parameter
- Format specifiers allow memory read (%x, %s, %p) and write (%n)
- Stack-based exploitation (format string reads stack arguments)
- Arbitrary read/write primitive when exploited

**Vulnerable patterns**:

```c
// VULNERABLE: User input as format string
printf(user_input);
fprintf(fp, user_input);
sprintf(buffer, user_input);
snprintf(buffer, size, user_input);
syslog(priority, user_input);

// SAFE: Format string is literal
printf("%s", user_input);
fprintf(fp, "Input: %s\n", user_input);
sprintf(buffer, "Data: %s", user_input);
```

**What to look for in decompiled code**:
```
Direct user input to format function:
  read(0, buffer, 256);
  printf(buffer);                    // VULNERABLE

Variable format string:
  char* fmt = get_format_string();   // Source from user
  printf(fmt, args);                 // VULNERABLE if fmt user-controlled

Missing format string:
  fprintf(stderr, error_msg);        // VULNERABLE if error_msg from user
```

**Exploitation primitives**:

```
%x or %p     → Leak stack values (addresses, canaries, pointers)
%s           → Arbitrary read (if pointer on stack)
%n           → Arbitrary write (writes byte count to pointer)
%N$x         → Direct parameter access (Nth argument)
%N$n         → Write to Nth argument pointer

Example attack:
  printf("AAAA%10$x");   → Leak 10th stack parameter
  printf("AAAA%7$n");    → Write to pointer at 7th stack position
```

**Investigation strategy**:
1. `search-decompilation` pattern="printf|fprintf|sprintf|snprintf|syslog"
2. `get-decompilation` at each match with includeContext=true
3. Check format string argument: Is it a constant string or variable?
4. If variable, trace source: Does it come from user input?
5. `set-bookmark` type="Warning" category="Format String" at vulnerability

**Telltale signs**:
- printf/fprintf with single argument (no format string literal)
- Format string stored in writable buffer
- User input copied into format string variable
- Error message formatted with user-supplied data

### Buffer Size vs. Operation Mismatch Patterns

**Conceptual characteristics**:
- Buffer allocated with one size
- Operation assumes different (larger) size
- Off-by-one errors
- Mismatched size calculations

**Common mismatch patterns**:

```c
// Wrong size constant
char buffer[64];
read(fd, buffer, 128);              // Reads 128 into 64-byte buffer

// Off-by-one
char buffer[64];
for (i = 0; i <= 64; i++)           // Loop goes to 64 (65 iterations)
    buffer[i] = input[i];           // Writes one byte past end

// Null terminator forgotten
char buffer[64];
strncpy(buffer, input, 64);         // May not null-terminate
printf("%s", buffer);               // Reads past end if not terminated

// Size calculation error
char buffer[64];
memcpy(buffer, src, strlen(src));   // strlen doesn't include null byte
                                    // But may overflow if strlen(src) >= 64
```

**What to look for in decompiled code**:
```
Size declaration:
  local_48 = buffer (char array, size 64)

Operation size:
  read(0, local_48, 0x80);          // 0x80 = 128 > 64

Offset calculation:
  local_48[iVar1] = input[iVar1];   // Check iVar1 bounds

Loop bounds:
  for (i = 0; i < size; i++)        // Is size validated?
      buffer[i] = input[i];         // Does size match buffer capacity?
```

**Investigation strategy**:
1. `get-decompilation` → Identify buffer size from local variable declaration
2. Find operations on buffer (read, memcpy, strcpy, loops)
3. Compare buffer size to operation size
4. `rename-variables` → buffer, buffer_size, read_size for clarity
5. `set-decompilation-comment` → "Buffer overflow: reads 128 into 64-byte buffer"
6. `set-bookmark` type="Warning" category="Size Mismatch"

**Telltale signs**:
- Magic constants in read/copy operations that don't match buffer size
- sizeof() used incorrectly (sizeof(pointer) vs. sizeof(array))
- Off-by-one in loop bounds (<= instead of <)
- Missing null terminator checks

### Integer Overflow Leading to Memory Corruption

**Conceptual characteristics**:
- Integer arithmetic wraps around at type bounds
- Overflow in size calculation leads to small allocation
- Small allocation leads to buffer overflow
- Underflow in bounds check bypasses security

**Vulnerable patterns**:

```c
// Allocation size overflow
uint32_t count = user_input;        // User controls this
uint32_t size = count * sizeof(element);  // May overflow
buffer = malloc(size);              // Allocates small buffer due to overflow
for (i = 0; i < count; i++)         // Loop uses original count
    buffer[i] = data[i];            // Heap overflow

// Bounds check underflow
size_t len = user_input;
if (len - 1 < MAX_SIZE) {           // Underflows if len == 0 (unsigned)
    memcpy(buffer, src, len);       // Large len bypasses check
}

// Sign confusion
int size = user_size;               // User controls, may be negative
if (size < MAX_SIZE) {              // Passes check if negative
    memcpy(buffer, src, size);      // Casted to size_t (huge number)
}
```

**What to look for in decompiled code**:
```
Size calculation:
  size = user_count * 16;           // Multiplication may overflow

Wraparound check missing:
  if (user_count < 1000) {          // Doesn't check for overflow
      size = user_count * 16;
      buf = malloc(size);
  }

Unsigned underflow:
  if (len - 1 < 1024) {             // What if len == 0?

Sign conversion:
  int signed_size = user_input;     // Signed integer
  malloc(signed_size);              // Casted to size_t (unsigned)
                                    // Negative becomes huge positive
```

**Investigation strategy**:
1. `search-decompilation` pattern="malloc|calloc|realloc"
2. Trace size parameter back to source
3. Check for multiplication/addition in size calculation
4. `change-variable-datatypes` to proper types (uint32_t, size_t, ssize_t)
5. Look for overflow checks (or lack thereof)
6. `set-decompilation-comment` → "Integer overflow: count * size may wrap"
7. `set-bookmark` type="Warning" category="Integer Overflow"

**Telltale signs**:
- Multiplication in allocation size without overflow check
- Unsigned subtraction in bounds check
- Signed/unsigned type confusion
- Missing validation for very large user-supplied sizes

### Use-After-Free Patterns

**Conceptual characteristics**:
- Memory freed but pointer still accessible (dangling pointer)
- Dangling pointer dereferenced (use after free)
- Heap allocator may reuse freed memory for new allocation
- Type confusion when old pointer accesses new object

**Vulnerable patterns**:

```c
// Classic use-after-free
object* ptr = malloc(sizeof(object));
use_object(ptr);
free(ptr);
// ... later in code ...
use_object(ptr);                     // Use after free!

// Double-free (special case)
free(ptr);
free(ptr);                           // Corrupts heap metadata

// Use-after-free via aliasing
object* ptr1 = malloc(sizeof(object));
object* ptr2 = ptr1;                 // Aliased pointer
free(ptr1);
use_object(ptr2);                    // Use after free via alias
```

**What to look for in decompiled code**:
```
Allocation and free:
  heap_ptr = malloc(0x40);
  // ... use heap_ptr ...
  free(heap_ptr);

Later usage (use-after-free):
  // ... some code ...
  *heap_ptr = value;                 // Write to freed memory
  function(heap_ptr);                // Pass freed pointer

Conditional free (double-free risk):
  if (condition1) free(ptr);
  if (condition2) free(ptr);         // May free twice if both true

No pointer nulling:
  free(ptr);
  // ptr not set to NULL, can be reused
```

**Investigation strategy**:
1. `search-decompilation` pattern="free"
2. For each free(), trace pointer usage after free
3. `find-cross-references` to pointer variable → See all uses
4. Check if pointer is nulled after free (ptr = NULL)
5. Check if pointer is checked before use (if (ptr != NULL))
6. `rename-variables` → freed_ptr, dangling_ptr for clarity
7. `set-decompilation-comment` at use site → "Use-after-free"
8. `set-bookmark` type="Warning" category="Use-After-Free"

**Telltale signs**:
- free() call without setting pointer to NULL
- Pointer dereferenced after free() in any code path
- Multiple free() calls on same pointer
- Pointer used in different contexts (freed as type A, used as type B)

### Heap Overflow Patterns

**Conceptual characteristics**:
- Allocation with one size
- Write operation exceeds allocated size
- Overflows into adjacent heap chunk
- Can corrupt heap metadata or adjacent object data

**Vulnerable patterns**:

```c
// Allocation too small
buffer = malloc(64);
read(fd, buffer, 128);              // Heap overflow

// Calculation error
buffer = malloc(count * sizeof(element));
for (i = 0; i <= count; i++)        // Off-by-one (should be <, not <=)
    buffer[i] = data[i];            // Overflows by one element

// Unchecked string operation on heap
buffer = malloc(64);
strcpy(buffer, user_input);         // Overflow if user_input > 63 bytes
```

**What to look for in decompiled code**:
```
Heap allocation:
  heap_buf = malloc(0x40);          // Allocates 64 bytes

Write operation:
  read(0, heap_buf, 0x100);         // Reads 256 bytes → overflow

Adjacent allocations:
  buf1 = malloc(0x40);
  buf2 = malloc(0x40);              // buf2 likely adjacent to buf1
  strcpy(buf1, user_input);         // May overflow into buf2

Metadata corruption risk:
  chunk = malloc(size);
  overflow_write(chunk, large_size);  // May corrupt next chunk's metadata
```

**Investigation strategy**:
1. `search-decompilation` pattern="malloc"
2. Trace allocated buffer through code
3. Find write operations on buffer (strcpy, memcpy, read, loops)
4. Compare allocation size to write size
5. Check for adjacent allocations (exploitation targets)
6. `set-decompilation-comment` → "Heap overflow: writes 256 into 64-byte allocation"
7. `set-bookmark` type="Warning" category="Heap Overflow"

**Telltale signs**:
- Small malloc() followed by large read/write
- String operations on heap buffers without bounds
- Loop writing to heap array without bounds check
- Multiple sequential allocations (heap layout predictable)

---

## Exploitation Primitive Patterns

### Arbitrary Memory Write Primitives

**Conceptual characteristics**:
- Ability to write controlled data to chosen address
- Achieved through various vulnerability classes
- Foundation for control flow hijacking and data corruption

**Primitive construction patterns**:

**Format string arbitrary write**:
```
// Concept: %n writes byte count to pointer argument
printf("AAAA%7$n");
// If stack[7] is controlled pointer, writes to *stack[7]

Technique:
1. Place target address on stack
2. Position format string to access it (%N$n)
3. Adjust byte count with padding to write desired value
4. Use width specifiers: %200c%7$n → writes 200+4=204
```

**Buffer overflow arbitrary write**:
```
// Concept: Overflow to overwrite pointer, then use pointer

Step 1: Overflow to corrupt pointer
[buffer overflow] → [overwrite ptr variable]

Step 2: Trigger write through pointer
*ptr = value;  // Writes to attacker-controlled address
```

**Heap overflow arbitrary write**:
```
// Concept: Overflow heap chunk to corrupt adjacent chunk's pointers

Chunk layout:
[chunk1 metadata][chunk1 data][chunk2 metadata][chunk2 data]

Overflow chunk1 data → overwrite chunk2 metadata → corrupt pointers
When chunk2 used, writes to attacker-controlled addresses
```

**Investigation strategy**:
1. Identify vulnerability (format string, overflow, use-after-free)
2. Analyze what can be overwritten
3. Trace pointer dereferencing after corruption
4. `set-bookmark` type="Analysis" category="Arbitrary Write" → Document primitive

**What enables arbitrary write**:
- Controlled pointer value (overflow, format string)
- Dereference of controlled pointer (assignment, function call)
- Heap metadata corruption (unlink exploitation)

### Arbitrary Memory Read Primitives

**Conceptual characteristics**:
- Ability to read from chosen memory address
- Used to leak addresses, canaries, code/data
- Critical for defeating ASLR and other protections

**Primitive construction patterns**:

**Format string arbitrary read**:
```
// Concept: %s reads string from pointer argument
printf("AAAA%10$s");
// If stack[10] is controlled pointer, prints string at *stack[10]

Technique:
1. Place target address on stack
2. Position format string to access it (%N$s)
3. Read output to obtain memory contents
```

**Uninitialized data read**:
```
// Concept: Uninitialized variables contain previous stack/heap data

Pattern in decompiled code:
  char buffer[64];
  // No initialization
  send(socket, buffer, 64, 0);      // Leaks stack contents

Investigation:
  Look for send/write without initialization
  Check if data used before written
```

**Buffer over-read**:
```
// Concept: Read past end of buffer into adjacent memory

Pattern:
  char buffer[64];
  strncpy(buffer, input, 64);       // No null termination
  printf("%s", buffer);             // Reads past end until null byte

Result: Leaks adjacent stack data
```

**Investigation strategy**:
1. Find format string vulnerabilities (user-controlled format)
2. Find uninitialized variables sent to output
3. Find string operations missing null termination
4. `set-bookmark` type="Analysis" category="Info Leak" → Document primitive
5. Calculate what can be leaked (addresses, canaries, pointers)

**What enables arbitrary read**:
- Format string with %s and controlled pointer
- Uninitialized buffer sent to network/file
- Missing null terminator allows over-read
- Heap use-after-free with read operations

### Control Flow Hijack Primitives

**Conceptual characteristics**:
- Redirect program execution to attacker-controlled location
- Achieved by overwriting function pointers or return addresses
- Goal: Execute shellcode, ROP chain, or existing functions

**Hijack target patterns**:

**Return address overwrite (stack overflow)**:
```
Stack layout:
[buffer][saved rbp][return address]

Overflow buffer → overwrite return address → redirect on function return

What to look for:
  Local buffer vulnerable to overflow
  Return address at predictable offset (buffer_size + 8 on x64)
  Calculate offset: buffer start to return address location
```

**Function pointer overwrite**:
```
// Global or heap-allocated function pointer
void (*callback)(void) = default_handler;

// Overflow to overwrite callback
buffer_overflow → overwrite callback pointer

// Trigger hijack
callback();  // Calls attacker-controlled address
```

**GOT/PLT overwrite**:
```
// Global Offset Table contains addresses of library functions
// Overwrite GOT entry to redirect library call

Example:
  Overwrite GOT[puts] with system address
  Next call to puts() actually calls system()

Requirement: Arbitrary write primitive to GOT address
```

**Virtual table (vtable) overwrite**:
```
// C++ objects have vtable pointers
// Overwrite vtable pointer to fake vtable

Object layout:
[vtable ptr][member1][member2]...

Overflow → overwrite vtable ptr → point to attacker-controlled memory
Virtual function call → uses fake vtable → hijacks control flow
```

**Investigation strategy**:
1. Identify overflow vulnerability
2. Determine what's adjacent in memory (return address, function pointer, vtable)
3. Calculate offset from buffer to target
4. `get-data` at GOT/PLT addresses → Get function pointer locations
5. `set-bookmark` type="Analysis" category="Control Flow Hijack"
6. Document target address and offset

**Telltale signs**:
- Function pointers in global variables or structures
- Indirect calls through function pointers
- Virtual function calls (C++ code)
- GOT/PLT entries for library functions

### Information Leak Primitives (Defeating ASLR)

**Conceptual characteristics**:
- Leak address from memory to defeat address randomization
- Calculate base addresses from leaked pointers
- Use leaked addresses in subsequent exploitation

**Leak source patterns**:

**Stack address leak**:
```
// Stack addresses often present on stack itself
Format string: printf("%p %p %p %p")  // Leak stack pointers
Uninitialized: Stack variable contains previous stack frame address

Use: Calculate stack layout, predict buffer addresses
```

**Code address leak (PIE bypass)**:
```
// Return addresses on stack point to code section
Format string leak of return address → code address
Calculate code base: leaked_addr & ~0xFFF (page alignment)

Use: Calculate gadget addresses, function addresses
```

**Libc address leak (ASLR bypass)**:
```
// GOT contains resolved libc function addresses
Arbitrary read of GOT entry → libc function address
Calculate libc base: leaked_addr - function_offset

Use: Calculate system(), one_gadget, useful function addresses
```

**Heap address leak**:
```
// Heap pointers often in freed chunks or stack
Use-after-free leak: Read freed chunk (contains fwd/bck pointers)
Format string: Leak heap pointer from stack

Use: Predict heap layout, target heap objects
```

**Investigation strategy**:
1. Identify leak primitive (format string, uninitialized data, over-read)
2. Determine what's leaked (stack, code, heap, libc addresses)
3. Calculate offsets to useful addresses
4. `set-bookmark` type="Note" category="Address Leak" → Document leak
5. `set-comment` → "Leaks libc address, calculate system() as libc_base + 0x4f4e0"

**Telltale signs**:
- printf with user-controlled format string
- Send/write with uninitialized buffer
- String operations without null termination
- Heap metadata visible to program (freed chunks)

---

## Common Exploitation Workflows

### Stack Overflow to Shell

**Attack flow**:
```
1. Find buffer overflow on stack
2. Calculate offset to return address
3. Identify target for hijack:
   a. Shellcode address (if NX disabled)
   b. system() address (if no ASLR)
   c. ROP chain address (if protections enabled)
4. Construct payload: [padding][return address][arguments/ROP]
5. Trigger overflow, return redirects to attacker code
6. Execute shellcode/system("/bin/sh") to get shell
```

**Investigation steps**:
1. `get-decompilation` of vulnerable function → Find buffer overflow
2. `rename-variables` → buffer, user_input, size
3. Calculate offset: buffer to return address (usually buffer_size + 8)
4. `search-strings-regex` pattern="/bin/sh" → Find shell string
5. `get-symbols` includeExternal=true → Find system() import
6. `set-bookmark` type="Analysis" category="Exploit Plan"
7. Document payload structure in comment

### Format String to Arbitrary Write

**Attack flow**:
```
1. Find printf(user_input) vulnerability
2. Test format string: Send "%x %x %x" → leak stack values
3. Find offset to controlled data on stack
4. Construct format string to write to arbitrary address:
   - Place target address on stack
   - Use %N$n to write to address at stack[N]
5. Target: Overwrite GOT entry, return address, or function pointer
6. Redirect execution to attacker code
```

**Investigation steps**:
1. `search-decompilation` pattern="printf|sprintf" → Find format string calls
2. `get-decompilation` with includeContext → Verify format string from user
3. `get-data` at GOT addresses → Identify targets for overwrite
4. Calculate stack offset to controlled buffer
5. `set-bookmark` type="Warning" category="Format String"
6. Document exploitation: "%7$n writes to address at stack[7]"

### Heap Exploitation to Code Execution

**Attack flow**:
```
1. Find heap vulnerability (use-after-free, heap overflow, double-free)
2. Understand heap layout (chunk sizes, allocation order)
3. Exploit heap corruption:
   a. Use-after-free: Free object, allocate new, use old pointer (type confusion)
   b. Heap overflow: Overflow chunk to corrupt adjacent chunk metadata
   c. Double-free: Corrupt freelist to allocate arbitrary address
4. Gain arbitrary write or control flow hijack primitive
5. Overwrite function pointer, GOT entry, or return address
6. Execute attacker code
```

**Investigation steps**:
1. `search-decompilation` pattern="malloc|free"
2. Trace allocation and free patterns
3. Identify vulnerability (use-after-free, overflow, double-free)
4. `rename-variables` → chunk1, chunk2, freed_ptr, size
5. Analyze adjacent allocations (overflow targets)
6. `set-bookmark` type="Warning" category="Heap Vulnerability"
7. Document exploitation primitive achieved

### Ret2libc (Return-to-libc)

**Attack flow**:
```
1. Find stack overflow vulnerability
2. Cannot use shellcode (NX enabled)
3. Redirect to existing libc function: system()
4. Set up arguments: First arg points to "/bin/sh"
5. Payload structure:
   - Overflow to return address
   - Overwrite return address → system() address
   - Set first argument → pointer to "/bin/sh" string
6. Function returns, calls system("/bin/sh"), spawns shell
```

**Investigation steps**:
1. `get-decompilation` → Find buffer overflow
2. `search-strings-regex` pattern="/bin/sh" → Get shell string address
3. `get-symbols` includeExternal=true → Find system import
4. Check calling convention (x86: stack args, x64: RDI register)
5. Calculate ROP gadgets if needed: pop rdi; ret
6. `set-bookmark` type="Note" category="Ret2libc Plan"
7. Document payload: [padding][system_addr][ret_addr]["/bin/sh"_ptr]

### ROP Chain Construction

**Attack flow**:
```
1. Find code execution vulnerability (overflow, etc.)
2. Protections prevent direct shellcode/ret2libc
3. Build ROP chain: Sequence of gadget addresses
4. Each gadget: Small code fragment ending in 'ret'
5. Chain gadgets to build desired operation (e.g., execve syscall)
6. Place chain on stack, trigger vulnerability
7. Execution flows through gadgets, performs desired operation
```

**Investigation steps**:
1. Identify required gadgets (pop rdi; ret, pop rsi; ret, syscall; ret, etc.)
2. Use external tool (ROPgadget) to find gadgets in binary/libc
3. `set-bookmark` type="Note" category="ROP Gadget" at each gadget address
4. `set-comment` at gadget address → "pop rdi; ret"
5. Document ROP chain structure:
   - [gadget1_addr] → pop rdi; ret
   - ["/bin/sh"_ptr] → argument for rdi
   - [gadget2_addr] → pop rsi; ret
   - [NULL] → argument for rsi
   - [syscall_addr] → execve syscall
6. `set-bookmark` type="Analysis" category="ROP Chain Plan"

---

## Protection Mechanism Bypass Patterns

### Stack Canary Bypass

**Canary mechanism**:
```
Stack layout with canary:
[buffer][stack canary][saved rbp][return address]

On function return:
  if (canary != expected_canary)
      __stack_chk_fail();  // Abort on corruption
```

**Bypass techniques**:

**1. Leak canary value (format string, uninitialized data)**:
```
printf(user_input);  // Format string leak
Send "%7$p" → leak canary from stack position 7
Include leaked canary in overflow payload to preserve it
```

**2. Brute-force canary (fork server)**:
```
If server forks instead of exiting:
  Canary same across fork
  Brute-force one byte at a time
  256 attempts per byte, 1024 total for 32-bit canary
```

**3. Overwrite without corrupting canary**:
```
Partial overwrite: Overflow only up to return address
Don't touch canary if it's not in the way
Or overwrite saved rbp and return address precisely
```

**Investigation**:
1. `search-decompilation` pattern="__stack_chk_fail" → Detect canary presence
2. `get-decompilation` → See canary check in code
3. Identify canary position on stack
4. `set-bookmark` type="Note" category="Stack Canary" → Document location
5. Plan bypass: leak, brute-force, or avoid

### NX/DEP Bypass (No Execute)

**Protection mechanism**:
```
Stack/heap marked non-executable
Shellcode injection doesn't work (causes segfault)
```

**Bypass techniques**:

**1. Return-to-libc (ret2libc)**:
```
Don't inject code, reuse existing code
Redirect to system(), execve(), etc.
Set up arguments properly
```

**2. Return-Oriented Programming (ROP)**:
```
Chain existing code fragments (gadgets)
Build complex operations from simple gadgets
No new code introduced
```

**3. mprotect/VirtualProtect ROP**:
```
Use ROP to call mprotect(shellcode_addr, RWX)
Change shellcode memory to executable
Jump to now-executable shellcode
```

**Investigation**:
1. `get-memory-blocks` → Check stack/heap permissions (look for 'x' flag)
2. If NX enabled, plan ROP or ret2libc
3. `get-symbols` includeExternal=true → Find usable functions
4. `set-bookmark` type="Analysis" category="NX Bypass"

### ASLR Bypass (Address Space Layout Randomization)

**Protection mechanism**:
```
Addresses randomized each execution
Code base, libc base, stack base, heap base all randomized
Exploit addresses must be dynamically calculated
```

**Bypass techniques**:

**1. Information leak**:
```
Leak address from memory (format string, uninitialized data)
Calculate base address from leaked pointer
Use base + offset to find desired functions
```

**2. Partial overwrite**:
```
Only lowest 12 bits (page offset) are not randomized
Overwrite only last byte of address
Reduces entropy, enables brute-force or partial redirect
```

**3. Heap spraying (rarely applicable in CTF)**:
```
Fill heap with controlled data
Increase probability of hitting controlled memory
```

**Investigation**:
1. Identify leak primitive (format string, over-read, uninitialized)
2. Calculate what's leaked (code, stack, heap, libc)
3. Determine offsets: leaked_addr to target_addr
4. `set-comment` → "Leak libc: system = libc_base + 0x4f4e0"
5. `set-bookmark` type="Analysis" category="ASLR Bypass"

### PIE Bypass (Position Independent Executable)

**Protection mechanism**:
```
Code section randomized (in addition to ASLR)
Function addresses, gadget addresses randomized
Cannot hardcode code addresses
```

**Bypass techniques**:

**1. Leak code address**:
```
Leak return address from stack → points to code
Calculate code base: leaked_addr & ~0xFFF
Calculate function/gadget addresses: code_base + offset
```

**2. Partial overwrite**:
```
Overwrite only last byte of return address
Redirect within same function or nearby functions
Useful for redirecting to existing win() function
```

**Investigation**:
1. Identify if PIE enabled (check binary properties)
2. Find code address leak (stack return address)
3. Calculate offsets from code base to targets
4. `set-bookmark` type="Analysis" category="PIE Bypass"

---

## Using This Reference

### Pattern Recognition Workflow

1. **Identify vulnerability class** → Match decompiled code to vulnerability patterns
2. **Determine exploitation primitive** → What capability does vulnerability provide?
3. **Check protections** → What bypass techniques are needed?
4. **Plan exploitation workflow** → Chain primitives to achieve goal
5. **Document in Ghidra** → Bookmarks, comments, renamed variables

### Investigation Priority

**Start with:**
1. Unsafe API recognition (strcpy, printf, etc.)
2. Buffer size vs. operation size comparison
3. Input flow tracing (where does user data go?)

**Then analyze:**
4. Memory layout (what's adjacent to vulnerable buffer?)
5. Available exploitation targets (return address, function pointers, GOT)
6. Protection mechanisms (canary, NX, ASLR, PIE)

**Finally plan:**
7. Exploitation primitive construction
8. Protection bypass strategy
9. Payload structure
10. Exploit execution plan

### Progressive Understanding

**First pass**: "Unsafe strcpy in main() on buffer[64]"
**Second pass**: "Overflow of 64 bytes to reach return address at offset +72"
**Third pass**: "Can redirect to system@plt, need '/bin/sh' string address"
**Fourth pass**: "Full ret2libc: overflow → system('/bin/sh') → shell"

Each iteration refines the exploitation plan.

### Evidence-Based Exploitation

Every claim needs evidence:
- "Buffer overflow exists" → Show buffer size < input size
- "Return address at offset 72" → Show stack layout calculation
- "Can call system()" → Show system@plt address or import
- "ASLR bypass possible" → Show leak primitive and calculation

Document all evidence with bookmarks and comments in Ghidra.
