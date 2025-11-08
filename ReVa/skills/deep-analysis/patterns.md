# Reverse Engineering Patterns Reference

This document contains higher-level patterns and concepts to recognize during deep analysis. Focus on algorithmic patterns, behavioral patterns, and code structure rather than platform-specific implementation details.

## Cryptographic Algorithm Patterns

### Block Cipher Recognition

**Conceptual characteristics:**
- **Substitution-Permutation Network (SPN)**: Repeated rounds of substitution (S-boxes) and permutation (bit shuffling)
- **Feistel Network**: Split data in half, operate on one half using the other as key input, swap halves, repeat
- **Fixed block size**: Typically 64 bits (DES, Blowfish) or 128 bits (AES)
- **Multiple rounds**: 8-16+ iterations of core transformation
- **Key schedule**: Derive round keys from master key

**What to look for in decompiled code:**
```
Nested loops:
  Outer: rounds (8, 10, 12, 14, 16, 32 iterations)
  Inner: processing blocks of fixed size

Array lookups (S-boxes):
  result = table[input_byte]
  Often 256-element arrays (0x100 size)

Bit manipulation:
  XOR, rotation (>> combined with <<), permutation

State updates:
  Array or struct representing current cipher state
  Transformed each round
```

**Telltale signs:**
- Large constant arrays (256+ bytes) that look like random data
- Fixed iteration counts (not data-dependent)
- Heavy use of XOR operations
- Byte-level array indexing: `array[data[i]]`

**Investigation strategy:**
1. `read-memory` at constant arrays - compare to known S-boxes
2. Count loop iterations - indicates cipher type/key size
3. `search-strings-regex` for algorithm names
4. Check cross-references to constants - find cipher initialization

### Stream Cipher Recognition

**Conceptual characteristics:**
- **Keystream generation**: Produce pseudo-random byte stream from key
- **Simple combination**: XOR plaintext with keystream
- **State-based**: Internal state evolves as keystream is produced
- **No fixed blocks**: Can encrypt arbitrary lengths

**What to look for:**
```
State initialization:
  Array or struct setup from key
  Often 256-byte arrays

Keystream generation loop:
  State updates via modular arithmetic
  Index computations: i = (i + 1) % N
  Swap operations common

XOR combination:
  output[i] = input[i] ^ keystream[i]
  Simple, obvious pattern
```

**Telltale signs:**
- Array swap operations: `temp = a[i]; a[i] = a[j]; a[j] = temp`
- Modulo operations: `% 256` or `& 0xFF`
- XOR in simple loop
- Smaller code footprint than block ciphers (no large constants)

### Public Key Cryptography Recognition

**Conceptual characteristics:**
- **Large integer arithmetic**: Numbers hundreds or thousands of bits
- **Modular exponentiation**: `result = base^exponent mod modulus`
- **Performance**: Very slow compared to symmetric crypto (indicates usage for key exchange, not bulk data)

**What to look for:**
```
Multi-precision arithmetic:
  Arrays representing big integers
  Functions for add/subtract/multiply on arrays

Square-and-multiply pattern:
  Loop over exponent bits
  Square operation each iteration
  Conditional multiply based on bit value

Modulo operations on large numbers:
  Division with large divisors
  Barrett reduction or Montgomery multiplication
```

**Telltale signs:**
- Very large buffers (128, 256, 512 bytes+)
- Bit-by-bit exponent processing
- Characteristic magic constants (e.g., 0x10001 = 65537 for RSA)
- Slow execution (thousands of operations per byte)

### Hash Function Recognition

**Conceptual characteristics:**
- **Compression function**: Transform fixed-size input to fixed-size output
- **Block processing**: Process data in chunks (512 bits typical)
- **State accumulation**: Running state updated with each block
- **Padding**: Add bytes to make input multiple of block size
- **One-way**: Lots of mixing, no reversibility

**What to look for:**
```
Initialization:
  Fixed magic constants
  MD5: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
  SHA-1: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
  SHA-256: 8 different constants

Round function:
  Fixed iteration count (64, 80 rounds)
  Lots of bitwise operations (rotations, XOR, AND, OR)
  State mixing (each output bit depends on many input bits)

Padding logic:
  Append 0x80 byte
  Length encoding at end
```

**Telltale signs:**
- Characteristic initialization constants
- Fixed 64 or 80 round loops
- Bitwise rotation: `(x << n) | (x >> (32-n))`
- Message schedule computation (W array expansion)

### Simple XOR Obfuscation

**Conceptual characteristics:**
- **Trivial operation**: `output = input XOR key`
- **Symmetric**: Encryption and decryption identical
- **Weak security**: Easy to break, used for obfuscation not protection

**What to look for:**
```
Single-byte key:
  for (i = 0; i < len; i++)
    data[i] ^= 0x42;

Multi-byte key:
  for (i = 0; i < len; i++)
    data[i] ^= key[i % keylen];

Rolling key:
  key = seed;
  for (i = 0; i < len; i++) {
    data[i] ^= key;
    key = update_key(key);  // LCG or similar
  }
```

**Telltale signs:**
- Very short functions (5-10 lines)
- XOR with constants or simple patterns
- Often applied to strings or config data
- Paired with static data arrays that need decoding

---

## Control Flow Patterns

### State Machine Recognition

**Conceptual characteristics:**
- **Explicit states**: Enumeration or integer representing current state
- **State transitions**: Switch/if-else on state variable
- **Event-driven**: External input triggers transitions

**What to look for:**
```
State variable:
  int state = INITIAL_STATE;

Dispatch loop:
  while (running) {
    switch (state) {
      case STATE_A: /* handle A, maybe transition to B */
      case STATE_B: /* handle B, maybe transition to C */
      ...
    }
  }

State tables (more advanced):
  next_state = transition_table[current_state][input];
  action = action_table[current_state][input];
```

**Telltale signs:**
- Large switch statements with many cases
- State variable repeatedly assigned new values
- Enumeration or #define constants for states
- Patterns like IDLE, CONNECTING, CONNECTED, DISCONNECTED

**Common uses:**
- Network protocol handling
- Parser implementation
- UI event handling
- Command processing

### Command Dispatcher Recognition

**Conceptual characteristics:**
- **Command codes**: Numeric identifiers for operations
- **Handler lookup**: Map command ID to handler function
- **Extensibility**: Easy to add new commands

**What to look for:**
```
Command dispatch table:
  switch (command_id) {
    case CMD_EXECUTE:  handle_execute(params); break;
    case CMD_UPLOAD:   handle_upload(params); break;
    case CMD_DOWNLOAD: handle_download(params); break;
    ...
  }

Function pointer table:
  handler = command_table[command_id];
  handler(params);

String-based dispatch:
  if (strcmp(cmd, "exec") == 0) handle_execute();
  else if (strcmp(cmd, "upload") == 0) handle_upload();
```

**Telltale signs:**
- Large switch on integer or string
- Array of function pointers
- Command ID constants or strings
- Common command names: exec, upload, download, shell, sleep, etc.

**Common uses:**
- Remote access tools (RAT)
- Backdoor command handling
- Plugin systems
- IPC/RPC mechanisms

### Callback Pattern Recognition

**Conceptual characteristics:**
- **Inversion of control**: Library calls your code, not you calling library
- **Function pointers**: Pass address of your function to framework
- **Asynchronous**: Often used for async operations

**What to look for:**
```
Callback registration:
  library_set_callback(MY_EVENT, my_handler_function);

Callback function signature:
  void my_callback(event_type, data, user_context)

Common callback contexts:
  - Network data received
  - Timer expired
  - File I/O complete
  - User interaction
```

**Telltale signs:**
- Function pointers passed as parameters
- Functions with generic names like "handler", "callback", "on_event"
- Often have opaque pointer parameter (void* user_data)

### Loop Patterns

**Simple iteration:**
```
for (i = 0; i < count; i++)
  - Linear processing
  - Transform/encrypt each element
```

**Nested loops (2D processing):**
```
for (i = 0; i < height; i++)
  for (j = 0; j < width; j++)
    - Image processing
    - Matrix operations
    - Block cipher on 2D state
```

**Do-while patterns:**
```
do {
  read_chunk();
  process_chunk();
} while (more_data);
  - File/network processing
  - Guaranteed first execution
```

**While-true with break:**
```
while (1) {
  if (condition) break;
  process();
}
  - Server loops
  - State machines
  - Event loops
```

---

## Data Structure Patterns

### Buffer Management

**Fixed-size buffers:**
```
char buffer[1024];
read(fd, buffer, sizeof(buffer));
  - Stack-allocated
  - Size known at compile time
  - Often seen with unsafe functions (strcpy, sprintf)
```

**Dynamic buffers:**
```
size = calculate_size();
buffer = malloc(size);
  - Heap-allocated
  - Size determined at runtime
  - Look for malloc/free pairs or memory leaks
```

**Ring buffers (circular):**
```
write_pos = (write_pos + 1) % BUFFER_SIZE;
read_pos = (read_pos + 1) % BUFFER_SIZE;
  - Fixed-size, reusable
  - Modulo arithmetic for wrap-around
  - Used in queues, streaming
```

### Linked Structures

**Linked list:**
```
struct node {
  data_type data;
  struct node* next;  // singly-linked
  struct node* prev;  // doubly-linked (optional)
};
```

**Recognition:**
- Pointer fields in structures
- Traversal loops: `while (node != NULL) { node = node->next; }`
- Insertion/deletion operations

**Tree structures:**
```
struct tree_node {
  data_type data;
  struct tree_node* left;
  struct tree_node* right;
};
```

**Recognition:**
- Two pointer fields (left/right)
- Recursive functions
- Comparison operations for ordering

### String Handling Patterns

**Length-prefixed strings:**
```
struct {
  uint32_t length;
  char data[];
}
```

**Null-terminated strings:**
```
while (*str != '\0') str++;  // strlen pattern
```

**Wide strings:**
```
wchar_t* wstr;
uint16_t* utf16_str;
  - 2 or 4 bytes per character
  - String operations work on larger units
```

**Detection:**
- Character-by-character loops
- Null byte checks
- String manipulation function calls
- UTF-8/UTF-16 encoding/decoding

---

## Network Protocol Patterns

### Protocol Structure Recognition

**Request-Response:**
```
send_request(command, params);
response = receive_response();
process_response(response);
```

**Characteristics:**
- Client initiates
- Server responds
- Blocking or polling wait for response
- Examples: HTTP, DNS, RPC

**Continuous Stream:**
```
while (connected) {
  data = receive_data();
  process_chunk(data);
}
```

**Characteristics:**
- Persistent connection
- Data flows continuously
- No strict request-response pairing
- Examples: video streaming, log shipping

**Message-Oriented:**
```
while (true) {
  message = receive_message();  // reads length, then payload
  dispatch_message(message);
}
```

**Characteristics:**
- Discrete messages with boundaries
- Length prefix or delimiter
- Message type/ID field
- Examples: custom C2 protocols, message queues

### Serialization Patterns

**Binary serialization:**
```
Write primitives in sequence:
  write_uint32(length);
  write_bytes(data, length);
  write_uint8(flags);
```

**Characteristics:**
- Dense, efficient
- Fixed byte order (endianness)
- Magic numbers for structure identification
- Version fields for compatibility

**Text-based serialization:**
```
JSON: {"key": "value", "num": 42}
XML: <root><item>value</item></root>
```

**Characteristics:**
- Human-readable
- Delimiter characters ({}, <>, quotes)
- String parsing and generation code
- Less efficient but more flexible

**Detection strategies:**
1. Look for sprintf/snprintf for text generation
2. Check for JSON/XML parsing libraries
3. Find memcpy sequences for binary packing
4. Identify byte-swapping (htonl/ntohl pattern)

### Connection Management

**Connection establishment pattern:**
```
Create socket
→ Connect to server
→ Send handshake/authentication
→ Receive acknowledgment
→ Enter main communication loop
```

**Connection pooling pattern:**
```
maintain pool of N connections
when request arrives:
  if free_connection available:
    use it
  else:
    create new connection (up to max)
after request:
  return connection to pool
```

**Reconnection pattern:**
```
max_retries = 5;
while (retries < max_retries) {
  if (connect_success) break;
  sleep(backoff_time);
  backoff_time *= 2;  // exponential backoff
  retries++;
}
```

**Telltale signs:**
- Retry loops with delays
- Connection state checking
- Timeout handling
- Fallback server lists

---

## Behavioral Patterns

### Encryption + Network (Data Exfiltration)

**Pattern sequence:**
```
1. Collect files/data
2. Compress (optional)
3. Encrypt
4. Send over network
5. Clean up local copies
```

**What to look for:**
- File enumeration → encryption function → network send
- Temporary file creation → processing → deletion
- Cross-reference encryption function to network functions

### Decrypt + Execute (Payload Loading)

**Pattern sequence:**
```
1. Read encrypted payload from resource/file/network
2. Decrypt in memory
3. Execute (direct call, injection, or create process)
```

**What to look for:**
- Buffer allocated with execute permissions
- Decryption function → function pointer cast → indirect call
- XOR loop → memory copy → execution transfer

### Time-Based Triggering

**Pattern:**
```
while (true) {
  current_time = get_time();
  if (current_time >= trigger_time) {
    execute_payload();
    break;
  }
  sleep(check_interval);
}
```

**What to look for:**
- Time/date API calls
- Comparison with specific dates
- Sleep/delay in loops
- Activation conditions based on temporal logic

### Polymorphic Behavior

**Pattern:**
```
code_variant = select_variant(seed);
decrypt_code(code_variant);
execute_decrypted_code();
re-encrypt_code(new_seed);
```

**What to look for:**
- Self-modifying code
- Multiple code variants
- Decryption before execution
- Encryption after execution
- Memory protection changes (read/write/execute toggling)

---

## Code Quality Indicators

### Hand-Written vs. Generated Code

**Hand-written characteristics:**
- Inconsistent formatting
- Comments (if not stripped)
- Meaningful variable names (if symbols present)
- Idiomatic patterns for the language
- Error handling mixed with logic

**Generated/compiled characteristics:**
- Very consistent structure
- Compiler optimization patterns
- Systematic variable naming (if stripped)
- Uniform error handling
- Recognizable library code patterns

### Obfuscated Code Indicators

**Deliberately obscured:**
- Meaningless variable/function names
- Unnecessary complexity
- Dead code branches
- Opaque predicates (always true/false conditions)
- Indirect calls through pointer manipulations
- String obfuscation

**Compiler optimizations (benign):**
- Loop unrolling
- Function inlining
- Constant folding
- Dead code elimination
- Register allocation patterns

**Distinction:** Obfuscation creates complexity without performance benefit; optimization creates complexity for performance.

### Library Code vs. Custom Code

**Library code:**
- Standard algorithms (qsort, hash functions)
- Consistent with open-source implementations
- Well-structured, parameterized
- Minimal dependencies on surrounding code

**Custom code:**
- Unique patterns
- Integrated with application logic
- Application-specific data structures
- More likely to have bugs/vulnerabilities

**Investigation priority:** Focus on custom code - that's where unique behavior lives.

---

## Using This Reference

### Pattern Matching Workflow

1. **Observe structure** - What loops, branches, data structures appear?
2. **Compare to patterns** - Does this match known algorithmic patterns?
3. **Verify with evidence** - Check for characteristic constants, operations, structure
4. **Document pattern** - Bookmark with pattern name for reference
5. **Improve code** - Rename variables/functions to reflect pattern (e.g., `aes_encrypt`, `rc4_keystream`)

### Example Investigation

```
Observation: Function with nested loops, array lookups, XOR operations

Compare: Matches "Block Cipher" or "Stream Cipher" patterns

Verify:
  - Check for large constant array (S-box?)
  - Count outer loop iterations (rounds?)
  - Look for key schedule function

Find: 256-byte array starting 63 7c 77 7b...
      14 iterations in outer loop

Conclusion: AES-256 (14 rounds, standard S-box)

Improve:
  rename-variables: state→aes_state, table→aes_sbox
  set-function-prototype: void aes_encrypt(uint8_t* data, uint8_t* key)
  set-comment: "AES-256 encryption using standard S-box"
```

### Pattern Combination

Real-world code combines multiple patterns:

**Example: Malware C2 Communication**
```
[Command Dispatcher] receives command from network
  ↓
[State Machine] tracks connection state
  ↓
[Callback Functions] handle specific commands
  ↓
[Buffer Management] manages received data
  ↓
[Encryption] protects command payloads
```

When you identify one pattern, look for related patterns in:
- Functions that call this one (higher-level orchestration)
- Functions called by this one (lower-level primitives)
- Cross-references to shared data structures

### Progressive Understanding

Don't need to identify every pattern perfectly:

**First pass:** "This looks like crypto (lots of XOR and loops)"
**Second pass:** "Probably a stream cipher (simple state, no large tables)"
**Third pass:** "Matches RC4 pattern (256-byte init, swap operations)"
**Fourth pass:** "Confirmed RC4 (found KSA and PRGA pattern)"

Each pass refines understanding and guides further investigation.
