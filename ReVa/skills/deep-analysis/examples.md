# Deep Analysis Skill - Investigation Examples

This document provides concrete examples of how to use the deep-analysis skill to answer specific reverse engineering questions.

## Example 1: "What does this function do?"

### Initial Question
User: "What does function `FUN_00401850` do?"

### Investigation Flow

**Phase 1: Initial Context (2 calls)**

1. Get decompilation with context:
```
get-decompilation FUN_00401850 limit=30
  includeIncomingReferences=true
  includeReferenceContext=true
```

Observe:
- Loop iterating 32 times
- Bitwise operations (XOR, shifts)
- Array access with computed indices
- Called by `process_buffer` and `send_encrypted_data`

2. Check cross-references:
```
find-cross-references location="0x401850" direction="to"
  includeContext=true contextLines=3
```

Observe:
- Called with 3 parameters: data buffer, length, key buffer
- Return value not checked
- Always passes 32-byte key buffer

**Phase 2: Pattern Recognition (2 calls)**

3. Read memory at constant data:
```
read-memory addressOrSymbol="0x404100" length=256
```

Find: Starts with `63 7c 77 7b f2 6b 6f c5...`

Compare: Matches AES S-box from patterns.md

4. Set initial bookmark:
```
set-bookmark type="Analysis" category="Crypto"
  addressOrSymbol="0x401850"
  comment="Investigating encryption function - appears to be AES"
```

**Phase 3: Iterative Improvement (6 calls)**

5. Rename key variables:
```
rename-variables FUN_00401850 {
  "param_1": "data",
  "param_2": "data_len",
  "param_3": "key",
  "local_10": "round",
  "local_14": "sbox_ptr"
}
```

6. Re-read to verify:
```
get-decompilation FUN_00401850 limit=30
```

Much clearer! Now see: `data[i] = sbox_ptr[data[i] ^ key[round]]`

7. Fix data types:
```
change-variable-datatypes FUN_00401850 {
  "data": "uint8_t*",
  "data_len": "size_t",
  "key": "uint8_t*",
  "sbox_ptr": "uint8_t*"
}
```

8. Set function prototype:
```
set-function-prototype location="0x401850"
  signature="void aes_encrypt_block(uint8_t* data, size_t len, uint8_t* key)"
```

9. Add documentation comment:
```
set-decompilation-comment FUN_00401850 line=15
  comment="AES S-box substitution - confirms AES encryption"
```

10. Document findings:
```
set-comment programPath="/malware.exe" addressOrSymbol="0x401850"
  type="pre"
  comment="AES encryption function: encrypts data in place using 32-round AES with S-box at 0x404100"
```

**Phase 4: Return Results**

### Answer
```json
{
  "question": "What does function FUN_00401850 do?",
  "answer": "Performs AES encryption on a data buffer in-place",
  "confidence": "high",
  "evidence": [
    "Uses standard AES S-box at 0x404100 (verified match: 63 7c 77 7b...)",
    "32-round loop structure typical of AES-256",
    "S-box substitution pattern at 0x401850:15",
    "Called with data, length, and 32-byte key parameters",
    "Invoked by send_encrypted_data and process_buffer functions"
  ],
  "assumptions": [
    {
      "assumption": "Function performs full AES encryption, not just one component",
      "evidence": "Complete 32-round structure with key schedule",
      "confidence": "high"
    }
  ],
  "improvements_made": [
    "Renamed 5 variables for clarity (data, data_len, key, round, sbox_ptr)",
    "Fixed 4 data types (uint8_t* for buffers, size_t for length)",
    "Set function prototype: void aes_encrypt_block(uint8_t* data, size_t len, uint8_t* key)",
    "Added decompilation comment on S-box substitution line",
    "Added address-level comment documenting AES usage"
  ],
  "unanswered_threads": [
    {
      "question": "Where does the 32-byte encryption key come from?",
      "starting_point": "Cross-references to aes_encrypt_block - check callers",
      "priority": "high",
      "context": "Key appears to be passed from calling functions, need to trace origin"
    },
    {
      "question": "What data is being encrypted?",
      "starting_point": "Functions process_buffer (0x402100) and send_encrypted_data (0x402500)",
      "priority": "high",
      "context": "These callers determine what data gets encrypted"
    },
    {
      "question": "Is this using proper AES mode (CBC, CTR, etc.) or just ECB?",
      "starting_point": "Examine calling context for IV usage or block chaining",
      "priority": "medium",
      "context": "Need to check if callers implement proper mode of operation"
    }
  ]
}
```

---

## Example 2: "Does this binary use encryption?"

### Initial Question
User: "Does this binary use encryption?"

### Investigation Flow

**Phase 1: Broad Discovery (3 calls)**

1. Search for crypto-related strings:
```
search-strings-regex pattern="(AES|RSA|encrypt|decrypt|crypto|cipher|key)"
  caseSensitive=false
```

Result: No obvious crypto strings found

2. Search decompiled code for patterns:
```
search-decompilation pattern="(\^|\&\s*0x(FF|ff)|<<|>>).*loop"
  maxResults=20
```

Find: Multiple functions with XOR and bitwise operations in loops

3. Check for suspicious imports:
```
get-symbols includeExternal=true include="named" startIndex=0 maxCount=200
```

Find: No obvious crypto library imports

**Phase 2: Investigate Candidates (4 calls)**

4. Check most suspicious function from search:
```
get-decompilation FUN_00402340 limit=40
  includeIncomingReferences=true
```

Observe: Nested loops, array indexing, modulo operations

5. Check for constant arrays:
```
find-cross-references location="0x402340" direction="from" limit=50
```

Find: References to 0x405000 (large data section)

6. Read suspicious memory region:
```
read-memory addressOrSymbol="0x405000" length=256
```

Find: Initialized array 0-255 in sequence, then modified

Pattern match: Looks like RC4 initialization!

7. Bookmark finding:
```
set-bookmark type="Analysis" category="Crypto"
  addressOrSymbol="0x402340"
  comment="Suspected RC4 cipher - 256-byte state array"
```

**Phase 3: Confirm Pattern (3 calls)**

8. Improve understanding:
```
rename-variables FUN_00402340 {
  "local_10": "state_array",
  "local_14": "i",
  "local_18": "j",
  "param_1": "key",
  "param_2": "key_len"
}
```

9. Re-examine:
```
get-decompilation FUN_00402340 limit=40
```

Clear RC4 key scheduling algorithm (KSA) pattern:
```c
for (i = 0; i < 256; i++) {
  state_array[i] = i;
}
j = 0;
for (i = 0; i < 256; i++) {
  j = (j + state_array[i] + key[i % key_len]) % 256;
  // swap state_array[i] and state_array[j]
}
```

10. Document:
```
set-comment programPath="/binary.exe" addressOrSymbol="0x402340"
  type="pre"
  comment="RC4 Key Scheduling Algorithm (KSA) - initializes cipher state from key"
```

**Phase 4: Return Results**

### Answer
```json
{
  "question": "Does this binary use encryption?",
  "answer": "Yes, uses RC4 stream cipher",
  "confidence": "high",
  "evidence": [
    "RC4 KSA (Key Scheduling Algorithm) at 0x402340",
    "256-byte state array initialization (0-255 sequence)",
    "Characteristic RC4 swap operations with modulo arithmetic",
    "State array modified based on key input",
    "Pattern matches RC4 specification exactly"
  ],
  "assumptions": [
    {
      "assumption": "RC4 PRGA (encryption loop) exists in separate function",
      "evidence": "KSA alone doesn't encrypt, must have companion function",
      "confidence": "medium"
    }
  ],
  "improvements_made": [
    "Renamed 5 variables in RC4 KSA function",
    "Documented RC4 KSA at 0x402340",
    "Set bookmark for crypto analysis"
  ],
  "unanswered_threads": [
    {
      "question": "Where is the RC4 PRGA (actual encryption) function?",
      "starting_point": "Check cross-references from KSA, likely called next",
      "priority": "high",
      "context": "KSA initializes state, PRGA uses it to encrypt"
    },
    {
      "question": "What is the RC4 key and where does it come from?",
      "starting_point": "Analyze callers of RC4 KSA at 0x402340",
      "priority": "high",
      "context": "Key parameter origin determines if hardcoded or derived"
    },
    {
      "question": "What data is being encrypted with RC4?",
      "starting_point": "Find PRGA function, then check its callers",
      "priority": "medium",
      "context": "Need to identify what sensitive data is being protected"
    }
  ]
}
```

---

## Example 3: "What is the C2 server address?"

### Initial Question
User: "What is the command and control server address?"

### Investigation Flow

**Phase 1: Search for Network Indicators (3 calls)**

1. Search for URLs and IPs:
```
search-strings-regex pattern="(https?://|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|\.com|\.net)"
  caseSensitive=false
```

Find: No obvious domain/IP strings

2. Search for network-related strings:
```
search-strings-regex pattern="(connect|server|host|port|callback|beacon)"
  caseSensitive=false
```

Find: String "host" at 0x404500

3. Check memory around "host" string:
```
read-memory addressOrSymbol="0x404500" length=64
```

Find: Encoded data following "host" string

**Phase 2: Find String Usage (3 calls)**

4. Find cross-references to suspicious string:
```
find-cross-references location="0x404500" direction="to"
  includeContext=true contextLines=4
```

Find: Referenced in FUN_00403000, looks like string decoding

5. Investigate decode function:
```
get-decompilation FUN_00403000 limit=30
  includeIncomingReferences=true
```

Observe: XOR loop decoding strings from 0x404500 region

6. Bookmark decode function:
```
set-bookmark type="Analysis" category="Obfuscation"
  addressOrSymbol="0x403000"
  comment="String decoding function - XOR with 0x42"
```

**Phase 3: Understand Decoding (4 calls)**

7. Improve decode function:
```
rename-variables FUN_00403000 {
  "param_1": "encoded_str",
  "param_2": "output_buf",
  "local_8": "i",
  "local_c": "str_len"
}
```

8. Add comment on decode logic:
```
set-decompilation-comment FUN_00403000 line=8
  comment="XOR decode with key 0x42 - reveals hidden strings"
```

9. Find where decoded string is used:
```
find-cross-references location="0x403000" direction="to"
  includeContext=true
```

Find: Called by FUN_00403500 (network initialization function)

10. Check network function:
```
get-decompilation FUN_00403500 limit=40
  includeIncomingReferences=true
  includeReferenceContext=true
```

Observe:
```c
decode_string(encoded_c2, hostname_buf);  // 0x403000
connect_to_server(hostname_buf, 443);
```

**Phase 4: Decode C2 Address (3 calls)**

11. Read encoded C2 address:
```
read-memory addressOrSymbol="0x404520" length=32
```

Get bytes: `2b 37 37 33 1a 0e 0e 6f 63 6c 6c 67 69 67 77 79 1e 65 6d 6f 00`

Manual decode (XOR with 0x42):
- 0x2b ^ 0x42 = 'i'
- 0x37 ^ 0x42 = 'u'
- 0x37 ^ 0x42 = 'u'
- Result: "iuuxy//evil-malware.com"

12. Document C2:
```
set-comment programPath="/malware.exe" addressOrSymbol="0x404520"
  type="pre"
  comment="Encoded C2 address (XOR 0x42): https://evil-malware.com"
```

13. Document network function:
```
set-comment programPath="/malware.exe" addressOrSymbol="0x403500"
  type="pre"
  comment="C2 connection function: decodes and connects to https://evil-malware.com:443"
```

**Phase 5: Return Results**

### Answer
```json
{
  "question": "What is the command and control server address?",
  "answer": "https://evil-malware.com (port 443)",
  "confidence": "high",
  "evidence": [
    "Encoded string at 0x404520 decodes to domain",
    "String decode function at 0x403000 uses XOR key 0x42",
    "Network init function at 0x403500 decodes and uses domain",
    "Connection established on port 443 (HTTPS)",
    "Manual decode confirmed: iuuxy// → https:// (XOR 0x42)"
  ],
  "assumptions": [
    {
      "assumption": "This is the only C2 address",
      "evidence": "Only encoded network string found so far",
      "confidence": "medium",
      "note": "May have fallback/backup C2 addresses"
    }
  ],
  "improvements_made": [
    "Renamed variables in decode function (0x403000)",
    "Added comments on XOR decode logic",
    "Documented decoded C2 address at storage location",
    "Documented C2 connection function"
  ],
  "unanswered_threads": [
    {
      "question": "Are there backup/fallback C2 addresses?",
      "starting_point": "Search for other encoded strings, check for C2 lists",
      "priority": "high",
      "context": "Malware often has multiple C2 servers for redundancy"
    },
    {
      "question": "What protocol is used for C2 communication?",
      "starting_point": "Analyze functions called after connect_to_server",
      "priority": "medium",
      "context": "Connects on port 443, likely HTTPS but may be custom"
    },
    {
      "question": "Is the C2 address hardcoded or can it be updated?",
      "starting_point": "Check for config file reading or domain generation",
      "priority": "medium",
      "context": "Dynamic C2 would indicate more sophisticated malware"
    }
  ]
}
```

---

## Example 4: "Fix the types in this function"

### Initial Question
User: "Fix the types in function `FUN_00402800` - the decompilation is confusing"

### Investigation Flow

**Phase 1: Understand Current State (2 calls)**

1. Get current decompilation:
```
get-decompilation FUN_00402800 limit=50
```

Observe confusing code:
```c
undefined4 FUN_00402800(int param_1, undefined4 param_2) {
  int iVar1;
  undefined4 *puVar2;
  undefined4 uVar3;

  iVar1 = *(int *)(param_1 + 4);
  puVar2 = (undefined4 *)(param_1 + 8);
  uVar3 = *puVar2;
  // ... more confusing code ...
}
```

2. Check cross-references for usage context:
```
find-cross-references location="0x402800" direction="to"
  includeContext=true contextLines=5
```

Observe: Called with pointer to structure, second param looks like a size

**Phase 2: Analyze Usage Patterns (3 calls)**

3. Check what fields are accessed:
- `param_1 + 0`: read as int
- `param_1 + 4`: read as int
- `param_1 + 8`: read as pointer
- Pattern: Structure with int, int, pointer fields

4. Check second parameter usage:
```
Search in decompilation for param_2 usage
```

Find: Used in comparison `if (iVar1 < param_2)` and loop counter
Conclusion: param_2 is a count/size, should be `size_t` or `uint32_t`

5. Check return value usage:
```
Check caller context from xrefs
```

Find: Return value compared to 0 and 1
Conclusion: Returns success/failure (bool or int status)

**Phase 3: Iterative Type Fixing (5 calls)**

6. Start with function signature:
```
set-function-prototype location="0x402800"
  signature="int process_items(struct item_list* list, uint32_t max_count)"
  createIfNotExists=false
```

7. Create structure for param_1:
```
parse-c-structure programPath="/binary.exe"
  cDefinition="struct item_list { uint32_t current_count; uint32_t total_count; void** items; };"
```

8. Apply structure to callers (check one caller):
```
Get address of a caller from xrefs: 0x403100
```

9. Fix variable types in function:
```
change-variable-datatypes FUN_00402800 {
  "iVar1": "uint32_t",
  "puVar2": "void**"
}
```

10. Rename variables for clarity:
```
rename-variables FUN_00402800 {
  "param_1": "list",
  "param_2": "max_count",
  "iVar1": "current_count",
  "puVar2": "items_array",
  "uVar3": "current_item"
}
```

**Phase 4: Verify and Document (3 calls)**

11. Re-read decompilation:
```
get-decompilation FUN_00402800 limit=50
```

Much better:
```c
int process_items(item_list* list, uint32_t max_count) {
  uint32_t current_count;
  void** items_array;
  void* current_item;

  current_count = list->total_count;
  items_array = list->items;
  current_item = *items_array;
  // ... clearer logic now ...
}
```

12. Add documentation:
```
set-decompilation-comment FUN_00402800 line=5
  comment="Iterates through item list up to max_count limit"
```

13. Document structure usage:
```
set-comment programPath="/binary.exe" addressOrSymbol="0x402800"
  type="pre"
  comment="Processes item_list structure: validates count and iterates items array"
```

**Phase 5: Return Results**

### Answer
```json
{
  "question": "Fix the types in function FUN_00402800",
  "answer": "Fixed - function processes item_list structure with count validation",
  "confidence": "high",
  "evidence": [
    "Structure pattern identified: int + int + pointer at offsets 0, 4, 8",
    "Second parameter used as loop bound (confirmed uint32_t)",
    "Return value used as boolean (0/1 success code)",
    "Cross-references confirm structure pointer usage",
    "Decompilation much clearer after type fixes"
  ],
  "improvements_made": [
    "Created item_list structure: { uint32_t current_count; uint32_t total_count; void** items; }",
    "Set function prototype: int process_items(item_list* list, uint32_t max_count)",
    "Fixed 2 variable types (uint32_t, void**)",
    "Renamed 5 variables for clarity (list, max_count, current_count, items_array, current_item)",
    "Added decompilation comment documenting behavior",
    "Added address-level comment on structure usage"
  ],
  "assumptions": [
    {
      "assumption": "items array contains void pointers (generic items)",
      "evidence": "No type-specific operations on items, just pointer manipulation",
      "confidence": "medium",
      "note": "Actual item type may be more specific"
    },
    {
      "assumption": "Structure is consistently used across codebase",
      "evidence": "Multiple callers use same access pattern",
      "confidence": "high"
    }
  ],
  "unanswered_threads": [
    {
      "question": "What is the actual type of items in the array?",
      "starting_point": "Check where items are allocated and how they're used",
      "priority": "medium",
      "context": "Currently typed as void** but may be more specific struct"
    },
    {
      "question": "Should item_list structure be applied at allocation sites?",
      "starting_point": "Find where item_list structures are created (malloc calls)",
      "priority": "low",
      "context": "Applying structure type at allocation improves consistency"
    },
    {
      "question": "Are there other functions using this structure that need fixing?",
      "starting_point": "Search for similar offset access patterns (param+0, param+4, param+8)",
      "priority": "medium",
      "context": "Consistent type usage across codebase aids understanding"
    }
  ]
}
```

---

## Key Takeaways from Examples

### Common Patterns Across Investigations

1. **Start broad, narrow focus**
   - Search/scan first
   - Identify candidates
   - Zoom into specific functions

2. **Iterate: Read → Improve → Verify**
   - Get decompilation
   - Rename/retype
   - Re-read to confirm improvement

3. **Follow the evidence**
   - Cross-references show usage
   - Memory reads reveal constants
   - Pattern matching confirms algorithms

4. **Document as you go**
   - Bookmarks for waypoints
   - Comments for findings
   - Keeps investigation organized

5. **Return actionable threads**
   - Always have next steps
   - Specific starting points
   - Prioritized by importance

### Tool Call Efficiency

Each example stayed within 10-15 tool calls:
- Example 1: 10 calls
- Example 2: 10 calls
- Example 3: 13 calls
- Example 4: 13 calls

This demonstrates staying focused and efficient while still gathering sufficient evidence and making meaningful improvements.

### Evidence-Based Conclusions

Every answer includes:
- Specific addresses
- Code patterns or constants found
- Cross-reference evidence
- Confidence level with rationale

This makes findings verifiable and trustworthy.
