# Deep Analysis examples

Two threads worked through the loop in `SKILL.md`. Addresses are illustrative.

## Example 1: trace the value to its producer

Question: "Where does it connect to?" Starting point: the import `connect`, from the survey's candidate threads. Closes when: the host and port are decoded and at their addresses. Refuted if: no call path reaches `connect`.

**Read.** `find-import-references` for `connect` gives one caller, `FUN_00402a10`. `get-decompilation` with `limit` 50: the first page is the signature and local declarations only. That is not a read (Paging). Next call: `offset` 51, `limit` 50.

```c
  local_c = FUN_00401b20(&DAT_0040b000, 7);
  local_10 = FUN_00401b20(&DAT_0040b008, 15);
  FUN_00401c80(local_118, local_c, local_10, 0);
  host = gethostbyname(local_118);
  ...
  sa.sin_port = htons(DAT_0040b018);
  connect(s, &sa, 0x10);
```

**Understand.** `local_118` is the host name. `FUN_00401c80` fills it. Assumption: `DAT_0040b018` is the port.

**Improve.** `rename-variables` in `FUN_00402a10`: `local_118` to `host_name`, `sa` to `server_addr`. `set-bookmark` with `type` `TODO`, `category` `Assumption`, comment `assumption: DAT_0040b018 is the C2 port — check: read its writers`.

**Follow (Callee).** Decompile `FUN_00401c80`:

```c
  for (p = param_2; p != NULL; p = va_arg(ap, char*)) strcat(param_1, p);
```

It only joins its arguments. It is not the producer, so the strings are not shown to be plaintext. Its inputs `local_c` and `local_10` come from `FUN_00401b20`, two lines above the call.

**Improve.** `set-function-prototype` on `FUN_00401c80`: `void str_concat(char *dst, ...)`. Comment it: "joins NULL-terminated argument list; not a decoder".

**Read.** Decompile `FUN_00401b20`:

```c
  for (i = 0; i < param_2; i++) out[i] = param_1[i] ^ (0x5a + i);
```

A rolling XOR with key `0x5a + i` (`patterns.md`). This is the producer.

**Improve.** `set-function-prototype`: `char * decode_rolling_xor(uint8_t *src, int len)`. `set-decompilation-comment` on the loop line: "rolling XOR, key 0x5a + i".

**Verify.** `read-memory` at `0x0040b000`, `length` 7: `2f 2b 38 3c 2a 3a 4e`. By hand: `0x2f ^ 0x5a` = `u`, `0x2b ^ 0x5b` = `p`, `0x38 ^ 0x5c` = `d`. Readable text, so the algorithm holds: the blob is `update.`. The blob at `0x0040b008` decodes the same way to `example-cdn.net`.

**Improve.** `set-comment` at `0x0040b000`: "decoded: update.". At `0x0040b008`: "decoded: example-cdn.net". `find-cross-references` `to` on `DAT_0040b018`: one write, the constant 443 in `FUN_00402100`. The assumption is confirmed: `create-label` `c2_port` at `0x0040b018`, then `remove-bookmark` the assumption.

**Thread end.** Answered. Thread report:

1. Answer: connects to update.example-cdn.net on port 443, host decoded at run time.
2. Confidence: high — the decoder was read and the bytes decode to readable text.
3. Evidence: `0x00402a10` calls `connect` with the joined host; `0x00401b20` rolling XOR `0x5a + i`; `0x0040b000` and `0x0040b008` encoded host parts; `0x00402100` writes 443 to `0x0040b018`.
4. Database writes: names `str_concat`, `decode_rolling_xor`, `c2_port`, `host_name`, `server_addr`; comments at `0x0040b000`, `0x0040b008`, the decoder loop and `str_concat`.
5. Assumptions: "DAT_0040b018 is the C2 port" created, then retired.
6. New threads: "Other callers of `decode_rolling_xor`?" — start `0x00401b20`, `TODO` bookmark set.

## Example 2: recover a structure

Question: "Recover the structure behind `param_1` in `FUN_00405e30`." Closes when: no raw offset on `param_1` remains in the function and its readers.

**Read.** `get-decompilation`, paged to the last line:

```c
  if (*(int *)(param_1 + 0x10) < *(int *)(param_1 + 0x14)) {
    *(undefined4 *)(*(int *)(param_1 + 0x48) + *(int *)(param_1 + 0x10) * 4) = param_2;
    *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + 1;
  }
  (**(code **)(param_1 + 0x4c))(param_1);
```

**Understand.** One line per offset:
- `0x10`, int, read and incremented: a count.
- `0x14`, int, compared with the count: a capacity.
- `0x48`, pointer to 4-byte items, indexed by the count: an item array.
- `0x4c`, function pointer called with the base: a callback.

**Follow.** `get-callers-decompiled` on `FUN_00405e30`. The caller `FUN_00405c00` allocates with `malloc(0x50)` and writes `0x00405d90` to `+ 0x4c`. Size: `0x50`.

**Improve (Typing tools first).** `parse-c-structure`:

```c
struct item_queue {
    uint8_t  pad_0x00[0x10];
    int      count;
    int      capacity;
    uint8_t  pad_0x18[0x30];
    uint32_t *items;
    void   (*on_push)(struct item_queue *q);
};
```

`set-function-prototype` on `FUN_00405e30`: `void item_queue_push(struct item_queue *q, uint32_t item)`. `change-variable-datatypes` in `FUN_00405c00`: the `malloc` result to `struct item_queue *`. `set-bookmark` with `type` `TODO`, `category` `Assumption`, comment `assumption: on_push notifies a consumer — check: decompile 0x00405d90`.

**Verify.** Re-read `item_queue_push`:

```c
  if (q->count < q->capacity) {
    q->items[q->count] = item;
    q->count = q->count + 1;
  }
  (*q->on_push)(q);
```

No raw offsets remain. Re-read `FUN_00405c00`: one access at `+ 0x18` shows as `pad_0x18[0]`. That field is real. Correct the definition with `uint32_t flags;` at `0x18` and `uint8_t pad_0x1c[0x2c];`, call `parse-c-structure` again, and re-read: the access now reads `q->flags`.

**Follow.** Decompile `0x00405d90`: it sets an event (`SetEvent` on Windows; the same shape is `pthread_cond_signal` on POSIX). The assumption is confirmed: `set-function-prototype` `void item_queue_signal(struct item_queue *q)`, `set-decompilation-comment` on the callback line in `item_queue_push` ("on_push: signals the consumer"), then `remove-bookmark` the assumption.

**Thread end.** Answered. Thread report:

1. Answer: `param_1` is a bounded queue of 32-bit items with a push callback; defined as `struct item_queue` (0x50 bytes).
2. Confidence: high — every access was read in the function and its allocator, and none is left raw.
3. Evidence: `0x00405e30` count and capacity at `0x10`/`0x14`, items at `0x48`, callback at `0x4c`; `0x00405c00` `malloc(0x50)` and the callback store.
4. Database writes: `struct item_queue`; prototypes of `item_queue_push` and `item_queue_signal`; the allocator's local typed; comment on the callback line.
5. Assumptions: "on_push notifies a consumer" created, then retired.
6. New threads: "What does `flags` at `0x18` control?" — start `0x00405c00`, `TODO` bookmark set. "Who consumes the queue?" — start `item_queue_signal`, `TODO` bookmark set.
