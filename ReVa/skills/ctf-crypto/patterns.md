# Cryptographic Pattern Recognition Reference

This document provides pattern recognition guides for identifying and analyzing cryptographic implementations in compiled binaries. These patterns are generic and apply across different algorithms - focus on conceptual characteristics, not specific implementations.

## General Crypto Recognition

### Crypto Presence Indicators

**High-confidence indicators:**
- Crypto-related strings: "encrypt", "decrypt", "cipher", "AES", "RSA", "key", "hash"
- Crypto library imports: CryptEncrypt, OpenSSL functions, libcrypto
- Large constant arrays (256+ bytes) with seemingly random data
- Heavy use of XOR operations
- Bitwise rotation patterns: `(x << n) | (x >> (32-n))`
- Fixed iteration counts (rounds): 8, 10, 12, 14, 16, 32, 64, 80
- Modular arithmetic on large integers

**Medium-confidence indicators:**
- Nested loops with array manipulations
- Byte-level array indexing patterns
- S-box style lookups: `output = table[input]`
- State transformation in fixed-size blocks

**What to check:**
```
search-strings-regex pattern="(encrypt|decrypt|crypto|cipher|AES|DES|RSA|RC4|key|hash|salt|iv)"
get-symbols includeExternal=true → Look for crypto API imports
search-decompilation pattern="(xor|sbox|round|permut)"
```

## Block Cipher Patterns

### Conceptual Characteristics

**Core concept**: Transform fixed-size data blocks through multiple rounds of substitution and permutation.

**Key identifying features:**
1. **Fixed block size**: Data processed in chunks (64 bits, 128 bits, etc.)
2. **Round structure**: Outer loop with fixed iteration count
3. **Substitution**: Table lookups (S-boxes) replacing input bytes
4. **Permutation**: Bit shuffling, rotation, mixing operations
5. **Key schedule**: Function deriving per-round keys from master key

**Generic code structure:**
```c
// Simplified conceptual pattern
void block_cipher_encrypt(uint8_t* data, uint8_t* key) {
    uint8_t round_keys[NUM_ROUNDS][KEY_SIZE];
    generate_round_keys(key, round_keys);

    for (int round = 0; round < NUM_ROUNDS; round++) {
        substitute_bytes(data);      // S-box lookups
        permute_bits(data);          // Bit shuffling
        mix_columns(data);           // Linear transformation
        add_round_key(data, round_keys[round]);  // XOR with round key
    }
}
```

### Substitution-Permutation Network (SPN)

**What it is**: Most modern block ciphers (AES, PRESENT, etc.)

**Recognition pattern:**
```
Loop structure:
  for round in 0..NUM_ROUNDS:
    1. SubBytes (S-box lookup)
    2. ShiftRows/PermuteBits (positional change)
    3. MixColumns (linear transformation)
    4. AddRoundKey (XOR with round key)

Characteristics:
  - Large constant arrays (S-boxes, typically 256 bytes)
  - Heavy XOR usage
  - Byte/word array indexing
  - State array (16+ bytes)
```

**AES-specific signatures:**
- S-box starting: 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5...
- Round counts: 10 (AES-128), 12 (AES-192), 14 (AES-256)
- 128-bit state (16 bytes, often as 4x4 matrix)
- Rcon (round constant) array for key expansion

**DES-specific signatures:**
- 64-bit blocks (8 bytes)
- 16 rounds
- Permutation tables (IP, FP)
- S-box arrays (8 boxes of 64 entries each)
- Feistel structure (see below)

### Feistel Network

**What it is**: Older block cipher design (DES, Blowfish, TEA)

**Recognition pattern:**
```
Loop structure:
  Split data into left and right halves
  for round in 0..NUM_ROUNDS:
    temp = right
    right = left XOR F(right, round_key[round])
    left = temp
  Swap and combine halves

Characteristics:
  - Data split in half
  - Swap operation each round
  - F-function (round function) operating on half the data
  - Other half XORed with F-function output
```

**Telltale code patterns:**
```c
// Feistel structure
uint32_t left = data[0];
uint32_t right = data[1];

for (int i = 0; i < rounds; i++) {
    uint32_t temp = right;
    right = left ^ f_function(right, key[i]);
    left = temp;
}
```

### Block Cipher Investigation Strategy

1. **Count rounds**: Outer loop iterations → Indicates cipher type and key size
2. **Measure block size**: How much data processed per iteration → 64-bit (DES) or 128-bit (AES)
3. **Identify S-boxes**: Large constant arrays → `read-memory` and compare to known S-boxes
4. **Check key schedule**: Look for function deriving multiple round keys from master key
5. **Recognize structure**: SPN (parallel operations) vs Feistel (swap pattern)

**Useful tools:**
```
get-decompilation limit=50 includeIncomingReferences=true
read-memory at constant array addresses
rename-variables: var_1 → sbox, var_2 → state, var_3 → round_key
```

## Stream Cipher Patterns

### Conceptual Characteristics

**Core concept**: Generate pseudo-random keystream from key, then XOR with plaintext.

**Key identifying features:**
1. **State-based generation**: Internal state evolves to produce keystream bytes
2. **Simple combination**: `ciphertext = plaintext XOR keystream`
3. **No fixed blocks**: Can encrypt arbitrary lengths
4. **Smaller code**: Less complex than block ciphers (no large S-boxes)
5. **Initialization**: State setup from key (KSA - Key Scheduling Algorithm)

**Generic code structure:**
```c
// Simplified conceptual pattern
void stream_cipher(uint8_t* data, size_t len, uint8_t* key) {
    uint8_t state[STATE_SIZE];
    initialize_state(state, key);  // KSA

    for (size_t i = 0; i < len; i++) {
        uint8_t keystream_byte = generate_next_byte(state);  // PRGA
        data[i] ^= keystream_byte;
    }
}
```

### RC4 Pattern (Most Common in CTFs)

**Recognition pattern:**
```
Initialization (KSA):
  state = [0, 1, 2, ..., 255]  // 256-byte array
  j = 0
  for i in 0..255:
    j = (j + state[i] + key[i % key_len]) % 256
    swap(state[i], state[j])

Keystream generation (PRGA):
  i = 0; j = 0
  for each byte:
    i = (i + 1) % 256
    j = (j + state[i]) % 256
    swap(state[i], state[j])
    keystream_byte = state[(state[i] + state[j]) % 256]
    output ^= keystream_byte
```

**Telltale signs:**
- 256-byte state array
- Swap operations: `temp = a[i]; a[i] = a[j]; a[j] = temp`
- Modulo 256 (`% 256` or `& 0xFF`)
- Index computations with running totals
- Two-phase structure (init, then generate)

### ChaCha/Salsa Pattern

**Recognition pattern:**
- 512-bit state (16 words of 32 bits)
- Quarter-round function (ARX: Add-Rotate-XOR)
- Magic constants: "expand 32-byte k" or "expand 16-byte k"
- 20 rounds (10 double-rounds) for ChaCha20
- Heavy use of 32-bit rotation

### Stream Cipher Investigation Strategy

1. **Find state initialization**: Look for array setup from key
2. **Identify update function**: How state evolves (swap, ARX, LCG, etc.)
3. **Locate XOR operation**: Simple `output = input ^ keystream`
4. **Check for reuse**: Is same keystream used multiple times? (weakness)
5. **Analyze state size**: 256 bytes (RC4), 64 bytes (ChaCha), variable (custom)

**Useful tools:**
```
search-decompilation pattern="swap|xor"
get-decompilation to see state evolution loop
rename-variables: var_1 → state, var_2 → keystream, var_3 → index
```

## Public Key Cryptography Patterns

### Conceptual Characteristics

**Core concept**: Asymmetric encryption using mathematical trapdoor functions.

**Key identifying features:**
1. **Large integer arithmetic**: Numbers hundreds or thousands of bits
2. **Modular exponentiation**: `result = base^exponent mod modulus`
3. **Very slow**: Orders of magnitude slower than symmetric crypto
4. **Multi-precision arithmetic**: Arrays representing big integers

**Generic code structure:**
```c
// Simplified modular exponentiation (square-and-multiply)
bigint modexp(bigint base, bigint exponent, bigint modulus) {
    bigint result = 1;
    while (exponent > 0) {
        if (exponent & 1) {
            result = (result * base) % modulus;  // Multiply
        }
        base = (base * base) % modulus;  // Square
        exponent >>= 1;
    }
    return result;
}
```

### RSA Pattern

**Recognition pattern:**
```
Key components:
  - Large modulus N (1024, 2048, 4096+ bits)
  - Public exponent e (often 65537 = 0x10001)
  - Private exponent d

Encryption: c = m^e mod N
Decryption: m = c^d mod N

Operations:
  - Modular exponentiation (square-and-multiply)
  - Multi-precision multiplication
  - Barrett or Montgomery reduction for modulo
```

**Telltale signs:**
- Very large buffers (128, 256, 512 bytes+)
- Magic constant 0x10001 (common RSA public exponent)
- Bit-by-bit processing of exponent
- Slow execution (many iterations)
- Functions for add/subtract/multiply on arrays

### Elliptic Curve Pattern

**Recognition pattern:**
- Point addition/doubling operations
- Affine or projective coordinates (x, y) or (x, y, z)
- Field arithmetic (modular arithmetic over prime field)
- Curve parameters (a, b, p, G, n)
- Scalar multiplication (point added to itself k times)

### Public Key Investigation Strategy

1. **Identify big integer operations**: Look for array-based arithmetic
2. **Find exponentiation pattern**: Square-and-multiply loop
3. **Extract parameters**: Modulus, exponent values from constants
4. **Check key size**: Buffer sizes indicate security level
5. **Look for weak parameters**: Small exponents, factorable moduli (CTF tricks)

**CTF-specific weaknesses:**
- Small modulus (factorizable)
- Small private exponent (Wiener's attack)
- Reused primes across multiple keys
- Textbook RSA (no padding, malleable)

## Hash Function Patterns

### Conceptual Characteristics

**Core concept**: One-way compression of arbitrary data to fixed-size digest.

**Key identifying features:**
1. **Initialization constants**: Fixed magic numbers unique to algorithm
2. **Block processing**: Data processed in chunks (512 bits typical)
3. **State accumulation**: Running state updated with each block
4. **Padding**: Append bits to make input multiple of block size
5. **Heavy mixing**: Lots of bitwise operations (irreversible)

**Generic code structure:**
```c
// Simplified hash structure
void hash(uint8_t* data, size_t len, uint8_t* digest) {
    uint32_t state[STATE_SIZE];
    initialize_state(state);  // Magic constants

    // Process each block
    for (each block in data) {
        process_block(state, block);  // Compression function
    }

    finalize(state, digest);  // Output transformation
}
```

### MD5/SHA Recognition

**MD5 initialization constants:**
```c
state[0] = 0x67452301;
state[1] = 0xefcdab89;
state[2] = 0x98badcfe;
state[3] = 0x10325476;
```

**SHA-1 initialization constants:**
```c
state[0] = 0x67452301;
state[1] = 0xefcdab89;
state[2] = 0x98badcfe;
state[3] = 0x10325476;
state[4] = 0xc3d2e1f0;
```

**SHA-256 initialization constants:**
```c
// First 32 bits of fractional parts of square roots of first 8 primes
state[0] = 0x6a09e667;
state[1] = 0xbb67ae85;
state[2] = 0x3c6ef372;
// ... 5 more
```

**Telltale signs:**
- Characteristic initialization constants (search for these!)
- Fixed round counts: 64 (MD5, SHA-256), 80 (SHA-1, SHA-512)
- Bitwise rotations: `(x << n) | (x >> (32-n))`
- Message schedule expansion (W array)
- Mixing functions (F, G, H functions in MD5)

### Hash Investigation Strategy

1. **Search for magic constants**: Hash functions have unique initializers
2. **Count rounds**: 64 or 80 iterations → Specific hash function
3. **Check block size**: 512 bits (MD5, SHA-1, SHA-256) or 1024 bits (SHA-512)
4. **Identify mixing operations**: AND, OR, XOR, NOT, rotation patterns
5. **Find padding logic**: Append 0x80, then zeros, then length

**Useful tools:**
```
search-decompilation pattern="0x67452301|0xefcdab89|0x98badcfe"
get-decompilation to see round structure
read-memory at initialization constants
```

## Simple Obfuscation Patterns

### XOR Cipher

**What it is**: Trivial encryption used for obfuscation, not security.

**Recognition pattern:**
```
Single-byte key:
  for (i = 0; i < len; i++)
    data[i] ^= 0x42;  // Fixed constant

Multi-byte key:
  for (i = 0; i < len; i++)
    data[i] ^= key[i % keylen];  // Repeating key

Rolling key (LCG-based):
  key = seed;
  for (i = 0; i < len; i++) {
    data[i] ^= key;
    key = (key * A + C) % M;  // Linear congruential generator
  }
```

**Telltale signs:**
- Very short functions (5-10 lines)
- XOR with constants or simple patterns
- Often applied to strings or config data
- No complex state or multiple rounds

**Breaking approach:**
- Single-byte: Brute-force (256 possibilities)
- Multi-byte: Frequency analysis or known-plaintext
- Rolling key: If LCG parameters known, reproduce sequence

### Substitution Cipher

**Recognition pattern:**
```
Simple substitution:
  for (i = 0; i < len; i++)
    output[i] = substitution_table[input[i]];

Caesar cipher (special case):
  for (i = 0; i < len; i++)
    output[i] = (input[i] + shift) % 256;
```

**Breaking approach:**
- Frequency analysis (if sufficient ciphertext)
- Known-plaintext attack
- Brute-force substitution table

### Custom Cipher Pattern

**What it is**: Challenge-specific encryption scheme not based on standards.

**Recognition indicators:**
- No match to known crypto patterns
- Unusual operations or data flow
- Mix of arithmetic, XOR, bit shifts in non-standard way
- Often simpler than real crypto (for solvability)

**Investigation strategy:**
1. **Document operations**: What transformations are applied, in what order?
2. **Identify invertibility**: Can operations be reversed?
3. **Look for weaknesses**:
   - Reduced keyspace (brute-forceable)
   - Linear operations (algebraically solvable)
   - Repeated patterns (exploitable structure)
4. **Known-plaintext**: If you have plaintext-ciphertext pairs, work backwards
5. **Replicate in Python**: Reproduce encryption logic, then reverse it

**Common CTF custom cipher weaknesses:**
- Insufficient mixing (partially recoverable plaintext)
- Weak key derivation (predictable)
- Reversible operations (decrypt by inverting)
- Small state space (brute-forceable)

## Recognition Workflow

### Step 1: Initial Detection
```
1. Search for crypto strings
   search-strings-regex pattern="(encrypt|decrypt|aes|rsa|md5|sha|key)"

2. Check for crypto API imports
   get-symbols includeExternal=true → Look for OpenSSL, Windows Crypto API

3. Search for crypto patterns in code
   search-decompilation pattern="(xor|sbox|round)"
```

### Step 2: Pattern Matching
```
4. Get decompilation of suspected function
   get-decompilation includeIncomingReferences=true

5. Compare to pattern categories:
   - Block cipher? (rounds, S-boxes, fixed blocks)
   - Stream cipher? (state, swap, XOR)
   - Hash? (magic constants, compression)
   - Public key? (big integers, modexp)
   - Simple obfuscation? (short, simple XOR)
```

### Step 3: Detailed Analysis
```
6. Read constant arrays
   read-memory at suspected S-box/constant locations

7. Compare to known values
   - AES S-box: 63 7c 77 7b...
   - MD5 init: 67452301 efcdab89...
   - RSA exponent: 0x10001

8. Count iterations
   - 10/12/14 rounds → AES
   - 16 rounds → DES
   - 64/80 rounds → Hash function
```

### Step 4: Verification
```
9. Rename variables for clarity
   rename-variables: var_1 → sbox, var_2 → key, var_3 → state

10. Document findings
    set-bookmark type="Analysis" category="Crypto"
    set-decompilation-comment line=N "AES encryption round"

11. Cross-check with usage
    find-cross-references → See where crypto is called, what data it processes
```

## CTF-Specific Patterns

### Key Management Anti-Patterns

**Hardcoded keys (most common):**
```c
uint8_t key[] = {0x41, 0x42, 0x43, ...};  // Key in .data section
encrypt(data, key);
```
**Finding**: `read-memory` at key array address

**Weak derivation:**
```c
// Time-based (predictable)
srand(time(NULL));
for (i = 0; i < keylen; i++)
    key[i] = rand() % 256;

// Constant seed (always same key)
srand(12345);
...
```
**Finding**: Analyze RNG initialization, predict or replicate

**User input as key (brute-force candidate):**
```c
scanf("%s", key);  // Short password
if (strlen(key) < 8) ...
```
**Finding**: Small keyspace, brute-forceable

### Implementation Bugs to Exploit

**ECB mode (block patterns visible):**
```c
for (i = 0; i < len; i += BLOCK_SIZE)
    encrypt_block(data + i, key);  // No chaining
```
**Weakness**: Identical plaintext blocks → identical ciphertext blocks

**IV reuse or zero IV:**
```c
uint8_t iv[16] = {0};  // Should be random!
```
**Weakness**: Breaks CBC security, enables attacks

**Reduced rounds (weak variant):**
```c
#define ROUNDS 4  // Should be 10+ for AES
```
**Weakness**: May be breakable with cryptanalysis tools

**Debug backdoor:**
```c
if (strcmp(password, "DEBUG") == 0)
    return decrypt_without_key(data);
```
**Finding**: Search for debug strings, test/admin backdoors

## Using This Reference

### Quick Lookup Process

1. **Identify general category**: Block/stream/hash/public-key/simple
2. **Match to specific pattern**: Compare code structure to examples
3. **Verify with evidence**: Check constants, round counts, operations
4. **Document in Ghidra**: Rename, retype, comment for clarity
5. **Investigate weaknesses**: Look for CTF-specific anti-patterns

### Example Investigation Flow

```
Observation: Function with loop, array access, XOR

1. Compare to patterns:
   - Block cipher? (Check for S-boxes, rounds)
   - Stream cipher? (Check for swap, state evolution)
   - Simple XOR? (Check function length)

2. Verify:
   - Read memory at constant array (if exists)
   - Count loop iterations
   - Check for characteristic operations

3. Identify:
   - Found 256-byte array with specific pattern
   - Swap operations in initialization
   - Simple XOR in second phase

4. Conclude: RC4 stream cipher

5. Improve:
   rename-variables: state, keystream, plaintext
   set-comment: "RC4 encryption with hardcoded key"

6. Exploit:
   Extract key from initialization
   Replicate RC4 in Python to decrypt
```

### Progressive Refinement

**First pass**: "This looks like crypto (XOR, loops, constants)"
**Second pass**: "Probably a block cipher (rounds, S-box pattern)"
**Third pass**: "Matches AES pattern (S-box signature, 10/12/14 rounds)"
**Fourth pass**: "AES-128 with hardcoded key at 0x405000"
**Fifth pass**: "Extracted key, successfully decrypted flag"

Each pass narrows down understanding and guides next investigation steps.

## Remember

- **Patterns are guidelines**, not rigid rules - CTF challenges may have variations
- **Constants are your friends** - Magic numbers uniquely identify algorithms
- **Structure reveals intent** - Loop patterns indicate algorithm type
- **CTF crypto is about implementation** - Look for weaknesses, not mathematical breaks
- **Document as you learn** - Rename variables to reflect your understanding
- **Verify with evidence** - Don't guess - compare constants, count rounds, check operations

Use this reference alongside the conceptual framework in SKILL.md to systematically identify and analyze cryptographic implementations.
