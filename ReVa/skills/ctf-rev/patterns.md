# CTF Reverse Engineering Pattern Recognition

This document provides pattern recognition guides for common CTF reverse engineering challenges. Focus on **identifying patterns quickly** to guide your solution strategy.

## Cryptographic Patterns

### Simple XOR Patterns

**Recognition Signature:**
```
Single-byte XOR:
  for (i = 0; i < len; i++)
    output[i] = input[i] ^ 0xKEY;

Multi-byte XOR (repeating key):
  for (i = 0; i < len; i++)
    output[i] = input[i] ^ key[i % keylen];

Rolling XOR:
  xor_val = seed;
  for (i = 0; i < len; i++) {
    output[i] = input[i] ^ xor_val;
    xor_val = next_value(xor_val);  // Linear congruential or similar
  }
```

**What to look for:**
- Very short functions (5-15 lines decompiled)
- XOR operation in loop
- Constant value or small array
- Modulo operation for key index (`i % keylen`)

**ReVa detection:**
```
search-decompilation pattern="\\^" caseSensitive=false
→ Find XOR operations

get-decompilation of suspicious function
→ Look for loop with XOR

read-memory at key location
→ Extract XOR key
```

**Solution approach:**
- XOR is self-inverse: `decrypt(x) = encrypt(x)`
- If you have ciphertext + key: plaintext = ciphertext XOR key
- If you have plaintext + ciphertext: key = plaintext XOR ciphertext
- If you have partial known plaintext: derive key, decrypt rest

### Base64 and Variants

**Recognition Signature:**
```
Character lookup table (64-character alphabet):
  Standard: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
  Custom: May use different alphabet

Bit manipulation:
  3 bytes → 4 encoded characters
  Shifting and masking: (data >> 18) & 0x3F

Padding:
  '=' characters or custom padding
```

**What to look for:**
- 64-character string constant (lookup table)
- Bit shifting: `>> 6`, `>> 12`, `>> 18`
- Masking: `& 0x3F` (6 bits)
- 3-to-4 or 4-to-3 byte conversion ratio
- Padding logic

**ReVa detection:**
```
search-strings-regex pattern="[A-Za-z0-9+/]{64}"
→ Find base64 alphabet

search-decompilation pattern="& 0x3f"
→ Find 6-bit masking (base64 characteristic)

get-decompilation of encoding function
→ Confirm 3→4 byte transformation
```

**Solution approach:**
- If standard base64: use standard decoder
- If custom alphabet: map custom → standard, then decode
- Reverse engineering: identify alphabet, implement decoder

### Block Cipher Patterns (AES, DES, etc.)

**Recognition Signature:**
```
AES characteristics:
  - 128-bit (16-byte) blocks
  - 10, 12, or 14 rounds (for 128, 192, 256-bit keys)
  - S-box: 256-byte constant array starting 63 7c 77 7b f2 6b 6f c5...
  - Mix columns, shift rows operations
  - Key schedule expansion

DES characteristics:
  - 64-bit (8-byte) blocks
  - 16 rounds
  - Permutation tables (IP, FP, E, P, S-boxes)
  - Feistel structure (split, swap, repeat)
```

**What to look for:**
```
Nested loops:
  for (round = 0; round < NUM_ROUNDS; round++)
    for (i = 0; i < BLOCK_SIZE; i++)
      state[i] = transform(state[i], key[round]);

Large constant arrays:
  uint8_t sbox[256] = {0x63, 0x7c, 0x77, ...};

Block processing:
  Fixed-size chunks (16 bytes for AES, 8 for DES)

Key schedule:
  Function deriving round keys from master key
```

**ReVa detection:**
```
search-decompilation pattern="(for.*round|for.*0x10)"
→ Find round loops

read-memory at constant arrays
→ Compare first bytes to known S-boxes:
   AES: 63 7c 77 7b f2 6b 6f c5
   DES S1: 0e 04 0d 01 02 0f 0b 08

get-decompilation with focus on nested loops
→ Count iterations (round count indicates key size)
```

**Solution approach:**
- Identify algorithm by S-box or constants
- Extract key from memory or key schedule
- Use standard implementation to decrypt
- For custom implementations, replicate in Python/C

### Stream Cipher Patterns (RC4, etc.)

**Recognition Signature:**
```
RC4 characteristics:
  KSA (Key Scheduling Algorithm):
    for i = 0 to 255: S[i] = i
    for i = 0 to 255: swap S[i] with S[(S[i] + key[i % keylen]) % 256]

  PRGA (Pseudo-Random Generation Algorithm):
    i = 0, j = 0
    while generating:
      i = (i + 1) % 256
      j = (j + S[i]) % 256
      swap(S[i], S[j])
      output = S[(S[i] + S[j]) % 256]
```

**What to look for:**
```
State array initialization:
  for (i = 0; i < 256; i++) state[i] = i;

Swap operations:
  temp = arr[i];
  arr[i] = arr[j];
  arr[j] = temp;

Modulo arithmetic:
  (i + 1) % 256
  index & 0xFF  (equivalent to % 256)

Simple XOR with keystream:
  output[i] = input[i] ^ keystream[i];
```

**ReVa detection:**
```
search-decompilation pattern="(swap|temp.*=.*\\[)"
→ Find array swap operations

get-decompilation of initialization
→ Look for 0-255 loop filling array

find-cross-references to state array
→ Trace usage through KSA and PRGA
```

**Solution approach:**
- Extract key from initialization
- Replicate KSA to generate initial state
- Replicate PRGA to generate keystream
- XOR ciphertext with keystream to decrypt

### Hash Function Patterns

**Recognition Signature:**
```
MD5/SHA characteristics:
  - Fixed initialization vectors (magic constants)
  - Block processing (512 bits / 64 bytes)
  - Multiple rounds (64 for MD5/SHA-256, 80 for SHA-1)
  - Bitwise operations: rotations, XOR, AND, OR, NOT
  - Padding: append 0x80, then zeros, then length

Magic constants:
  MD5: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
  SHA-1: adds 0xc3d2e1f0
  SHA-256: Eight 32-bit constants derived from square roots
```

**What to look for:**
```
Characteristic constants:
  Search for 0x67452301 (MD5/SHA-1 IV)

Fixed round counts:
  for (round = 0; round < 64; round++)  // MD5, SHA-256
  for (round = 0; round < 80; round++)  // SHA-1

Bitwise rotation macros:
  ROTL(x, n) = (x << n) | (x >> (32-n))

Message schedule (W array):
  Expands 16 input words to 64/80 words

Padding logic:
  Append 0x80, zeros, then 64-bit length
```

**ReVa detection:**
```
search-decompilation pattern="0x67452301"
→ Find MD5/SHA initialization

read-memory at round constants
→ Identify specific hash variant

get-decompilation of hash function
→ Count rounds, identify structure
```

**Solution approach:**
- Hash functions are one-way (cannot decrypt)
- If you find hash of flag: need to brute force or use known input
- If you find comparison: extract expected hash, try common flags
- Check for weak hash (MD5, SHA-1) or short input (brute-forceable)

## Encoding Patterns

### Character Substitution

**Recognition Signature:**
```
Lookup table mapping:
  output[i] = table[input[i]];

Caesar cipher (shift):
  output[i] = (input[i] - 'A' + shift) % 26 + 'A';

Custom alphabet:
  const char* alphabet = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba";
  output[i] = alphabet[input[i] - 'A'];
```

**What to look for:**
- Character array constants (alphabets, substitution tables)
- Character-by-character processing loops
- Range checks: `if (c >= 'A' && c <= 'Z')`
- Arithmetic on character codes: `c - 'A'`, `c + shift`

**ReVa detection:**
```
search-strings-regex pattern="[A-Z]{26}"
→ Find alphabet strings

search-decompilation pattern="(- 'A'|% 26)"
→ Find character arithmetic

get-decompilation of encoding function
→ Identify substitution pattern
```

**Solution approach:**
- Extract substitution table or shift value
- Build reverse mapping
- Apply to encoded data

### Binary-to-Text Encodings

**Recognition Signature:**
```
Hex encoding:
  "0123456789abcdef"
  nibble_high = (byte >> 4) & 0xF;
  nibble_low = byte & 0xF;

Binary/ASCII:
  Converting to "01011010" strings

Custom encodings:
  Mapping bytes to multi-character sequences
```

**What to look for:**
- Hex digit strings
- Bit extraction: `>> 4`, `& 0xF`, `& 1`
- Character code generation loops
- 1-to-2 or 1-to-8 byte expansion

**ReVa detection:**
```
search-decompilation pattern="(>> 4|& 0xf)"
→ Find nibble extraction (hex encoding)

get-strings to find encoding alphabets
→ Check for hex, binary digit strings
```

**Solution approach:**
- Identify encoding scheme
- Implement decoder
- Apply to encoded flag

## Input Validation Patterns

### Character-by-Character Comparison

**Recognition Signature:**
```
Direct comparison:
  for (i = 0; i < len; i++)
    if (input[i] != expected[i])
      return 0;
  return 1;

Comparison with transformation:
  for (i = 0; i < len; i++)
    if (transform(input[i]) != expected[i])
      return 0;
```

**What to look for:**
- Loop over input length
- Comparison inside loop: `!=`, `==`
- Early return on mismatch
- Success after full loop completion

**ReVa detection:**
```
search-decompilation pattern="(if.*!=|if.*==)"
→ Find comparison operations

get-decompilation of validation function
→ Identify loop structure

read-memory at expected value array
→ Extract expected bytes
```

**Solution approach:**
- If direct comparison: read expected array, that's the flag
- If transformed comparison: reverse transformation
- If complex transformation: trace each character

### Checksum Validation

**Recognition Signature:**
```
Sum check:
  sum = 0;
  for (i = 0; i < len; i++)
    sum += input[i];
  return (sum == EXPECTED_SUM);

XOR check:
  xor = 0;
  for (i = 0; i < len; i++)
    xor ^= input[i];
  return (xor == EXPECTED_XOR);

Custom accumulation:
  result = SEED;
  for (i = 0; i < len; i++)
    result = (result * MULT + input[i]) % MOD;
  return (result == EXPECTED);
```

**What to look for:**
- Accumulator variable (sum, product, xor)
- Loop updating accumulator
- Final comparison to constant
- May be combined with other checks

**ReVa detection:**
```
search-decompilation pattern="(\\+=|\\*=|\\^=)"
→ Find accumulator updates

get-decompilation of validation
→ Identify accumulation pattern

read-memory at expected value
→ Extract target checksum
```

**Solution approach:**
- Single checksum: underconstrained (many solutions)
- Multiple checksums: may uniquely identify input
- Extract all constraints, solve as system of equations

### Constraint-Based Validation

**Recognition Signature:**
```
Multiple independent checks:
  if (input[0] + input[1] != 0x64) return 0;
  if (input[0] - input[1] != 0x14) return 0;
  if (input[2] ^ 0x42 != 0x33) return 0;
  if (input[3] * 2 == input[4]) return 0;
  return 1;

Relational constraints:
  if (input[i] != input[j] + 5) return 0;
```

**What to look for:**
- Multiple if-statements with comparisons
- Arithmetic operations on input elements
- Relationships between different input positions
- Constants in comparisons

**ReVa detection:**
```
get-decompilation of validation function
→ Identify all comparison statements

set-decompilation-comment on each constraint
→ Document relationships

Extract to external solver:
→ List all constraints, solve with z3 or similar
```

**Solution approach:**
- Extract all constraints
- Frame as system of equations
- Solve using constraint solver (z3, SMT)
- Verify solution satisfies all constraints

## Algorithm Patterns

### Mathematical Sequences

**Recognition Signature:**
```
Fibonacci:
  a = 0, b = 1;
  while (...) {
    next = a + b;
    a = b;
    b = next;
  }

Factorial:
  result = 1;
  for (i = 1; i <= n; i++)
    result *= i;

Prime checking:
  for (i = 2; i < sqrt(n); i++)
    if (n % i == 0) return 0;
  return 1;
```

**What to look for:**
- Iterative or recursive patterns
- Arithmetic progressions
- Number theory operations (modulo, divisibility)
- Known sequence generation

**ReVa detection:**
```
search-decompilation pattern="(fibonacci|factorial|prime)"
→ Find named functions (if not stripped)

get-decompilation of suspicious function
→ Identify mathematical pattern

Recognize by structure:
→ Two-variable update (Fibonacci)
→ Multiplication accumulator (factorial)
→ Modulo divisibility (prime check)
```

**Solution approach:**
- Recognize the algorithm
- Understand how it validates input
- Derive required input or replicate logic

### Matrix Operations

**Recognition Signature:**
```
Matrix multiplication:
  for (i = 0; i < rows; i++)
    for (j = 0; j < cols; j++)
      for (k = 0; k < inner; k++)
        result[i][j] += a[i][k] * b[k][j];

Linear transformations:
  output[i] = matrix[i][0] * input[0] + matrix[i][1] * input[1] + ...;
```

**What to look for:**
- Triple-nested loops (matrix multiply)
- 2D array indexing: `array[i][j]` or `array[i * width + j]`
- Accumulator in inner loop
- Linear combinations of input

**ReVa detection:**
```
search-decompilation pattern="\\[.*\\]\\[.*\\]"
→ Find 2D array access

get-decompilation showing nested loops
→ Count loop depth (3 = likely matrix multiply)

read-memory at matrix constants
→ Extract transformation matrix
```

**Solution approach:**
- Extract matrix
- Invert matrix (if square and invertible)
- Apply inverse to expected output to get required input

### State Machine Patterns

**Recognition Signature:**
```
Explicit state variable:
  int state = STATE_INIT;
  while (running) {
    switch (state) {
      case STATE_INIT: /* ... */ state = STATE_READY; break;
      case STATE_READY: /* ... */ state = STATE_PROCESS; break;
      case STATE_PROCESS: /* ... */ state = STATE_DONE; break;
    }
  }

Implicit state (position in input):
  for (i = 0; i < len; i++) {
    if (/* condition based on i and input */)
      /* different processing for different positions */
  }
```

**What to look for:**
- State variable with multiple values
- Large switch statement on state
- State transitions (state = NEW_STATE)
- Different behavior based on current state

**ReVa detection:**
```
search-decompilation pattern="(case|switch)"
→ Find switch statements

get-decompilation of state machine
→ Map state transitions

rename-variables to clarify states
→ current_state, next_state, etc.
```

**Solution approach:**
- Map state transition graph
- Identify accepting states (success)
- Determine input sequence that reaches accepting state

## Obfuscation Patterns

### Control Flow Obfuscation

**Recognition Signature:**
```
Opaque predicates (always true/false):
  if (x * x >= 0)  // Always true
    real_code();
  else
    never_executed();

Dispatcher loops:
  while (1) {
    switch (dispatch_value) {
      case 0: /* block A */; dispatch_value = 5; break;
      case 5: /* block B */; dispatch_value = 2; break;
      case 2: /* block C */; dispatch_value = -1; break;
      case -1: return;
    }
  }
```

**What to look for:**
- Unnecessary conditionals
- Complex control flow with simple logic
- Dispatcher-based execution (case jumps)
- Dead code branches

**ReVa detection:**
```
get-decompilation of obfuscated function
→ Look for unusual control flow

set-bookmark type="Warning" for suspicious patterns
→ Mark opaque predicates, dispatchers

Focus on data flow, ignore control flow complexity
→ Track input transformation regardless of jumps
```

**Solution approach:**
- Ignore obfuscation, trace data flow
- Use dynamic analysis to observe actual execution path
- Simplify manually or with deobfuscation tools

### String Obfuscation

**Recognition Signature:**
```
Stack strings (character-by-character):
  str[0] = 'f'; str[1] = 'l'; str[2] = 'a'; str[3] = 'g';

Encrypted strings (decrypted at runtime):
  decrypt_string(encrypted_data, key, output);

Computed strings:
  for (i = 0; i < len; i++)
    str[i] = base[i] ^ key;
```

**What to look for:**
- Character assignments to array
- String decryption functions
- XOR or arithmetic on character arrays
- Strings not visible in static string list

**ReVa detection:**
```
get-strings may not show obfuscated strings
→ Use decompilation to find construction

search-decompilation pattern="\\[0\\] = "
→ Find character-by-character assignments

find-cross-references to decryption functions
→ Locate where strings are revealed
```

**Solution approach:**
- Identify deobfuscation routine
- Extract encrypted data and key
- Decrypt manually or use dynamic analysis to observe decrypted string

### Anti-Debugging (CTF Context)

**Recognition Signature:**
```
Debugger detection:
  if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) exit(1);  // Linux
  if (IsDebuggerPresent()) exit(1);  // Windows

Timing checks:
  start = time();
  /* short operation */
  end = time();
  if (end - start > THRESHOLD) exit(1);  // Detected breakpoint delay

Self-modification:
  Decrypt code section at runtime
  Execute decrypted code
  Re-encrypt afterwards
```

**What to look for:**
- Debugger detection APIs
- Timing measurements
- Memory protection changes
- Code modification at runtime

**ReVa detection:**
```
get-symbols includeExternal=true
→ Look for: ptrace, IsDebuggerPresent, time, gettimeofday

search-decompilation pattern="(ptrace|IsDebugger|time)"
→ Find anti-debug checks

find-cross-references to VirtualProtect, mprotect
→ Identify self-modifying code
```

**Solution approach:**
- Patch out anti-debug checks (NOP the exit)
- Use anti-anti-debugging tools
- Analyze in sandbox that hides debugger
- For CTF, often acceptable to patch binary

## Common CTF Tricks

### Flag Format Validation

**Pattern:**
```
Check prefix:
  if (strncmp(input, "flag{", 5) != 0) return 0;

Check suffix:
  if (input[len-1] != '}') return 0;

Check length:
  if (strlen(input) != EXPECTED_LEN) return 0;
```

**What to look for:**
- String comparison with literal "flag{" or "CTF{"
- Bracket/brace checks
- Length validation

**ReVa detection:**
```
search-strings-regex pattern="(flag\\{|CTF\\{)"
→ Find flag format strings

get-decompilation of validation
→ Extract format requirements
```

**Solution approach:**
- Note format requirements
- Focus on solving for content between delimiters
- Reconstruct full flag with proper format

### Multi-Stage Validation

**Pattern:**
```
Stage 1: Check format (flag{...})
Stage 2: Check length (must be 32 characters)
Stage 3: Check checksum (sum must equal X)
Stage 4: Check encryption (encrypted content matches Y)
```

**What to look for:**
- Multiple validation functions called in sequence
- Early exits on failure
- Progressive constraints

**ReVa detection:**
```
find-cross-references to validation function
→ See if called from multi-stage validator

get-decompilation of main validator
→ Identify call sequence

Analyze each stage separately
→ Understand cumulative constraints
```

**Solution approach:**
- Solve each stage's constraints
- Combine solutions (flag must satisfy ALL stages)
- Work backwards from most constrained to least

### Hidden Success Path

**Pattern:**
```
Obvious failure message:
  printf("Wrong!\n");

Hidden success logic:
  if (/* complex condition */)
    system("cat /flag.txt");  // No message, just action
```

**What to look for:**
- Success action without visible message
- File access (cat flag, open flag.txt)
- Network communication of flag
- Success indicated by lack of "Wrong" message

**ReVa detection:**
```
search-strings-regex pattern="(flag|/flag|flag\\.txt)"
→ Find flag file references

find-cross-references to flag file
→ Locate success path

get-decompilation of success condition
→ Understand requirements
```

**Solution approach:**
- Don't rely on "Correct!" message
- Look for flag output actions
- Check for file reads, network sends
- Success may be silent

## Using These Patterns

### Pattern Matching Workflow

1. **Observe code structure**
   - Loops, conditionals, function calls
   - Data types, array sizes
   - Constants and literals

2. **Compare to pattern catalog**
   - Does this match a crypto pattern?
   - Is this an encoding scheme?
   - Looks like input validation?

3. **Verify with specific checks**
   ```
   Hypothesis: This is AES
   Check 1: read-memory at constant array → Matches AES S-box? ✓
   Check 2: Count loop iterations → 10, 12, or 14? ✓
   Check 3: Block size 16 bytes? ✓
   Conclusion: AES confirmed
   ```

4. **Apply pattern-specific solution**
   - AES → Extract key, decrypt
   - XOR → Extract key, XOR again
   - Constraint validation → Extract constraints, solve

### Quick Reference Decision Tree

```
Does it have loops with XOR?
  → Check Simple XOR Patterns

Does it have large constant arrays?
  → Check Block Cipher or Hash Patterns

Does it have swap operations and modulo?
  → Check Stream Cipher Patterns

Does it have character-by-character comparison?
  → Check Input Validation Patterns

Does it have 64-character lookup table?
  → Check Base64 Pattern

Does it have mathematical operations (factorial, fibonacci)?
  → Check Algorithm Patterns

Is control flow overly complex?
  → Check Obfuscation Patterns
```

### Combining Patterns

Real challenges often combine multiple patterns:

**Example: Crypto + Validation**
```
Input → Format Check (flag{...}) → XOR Decode → AES Decrypt → Compare to Expected
```

**Solve:**
1. Extract format requirements
2. Identify XOR key
3. Identify AES key
4. Extract expected value
5. Work backwards: AES_decrypt(XOR_decode(expected)) with known keys

**Example: Encoding + Constraint**
```
Input → Base64 Decode → Constraint Check (sum == X, product == Y)
```

**Solve:**
1. Extract constraints on decoded values
2. Solve constraints
3. Base64 encode solution

## Remember

Patterns are **recognition shortcuts**, not rigid rules:
- Use patterns to quickly identify challenge type
- Adapt pattern solutions to specific implementation
- If pattern doesn't fit, analyze from first principles
- Document your pattern matches with bookmarks/comments
- Build your own pattern library from experience

When you recognize a pattern, you skip hours of analysis and jump directly to solution strategy.
