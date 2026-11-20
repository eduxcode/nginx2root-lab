# RCE: what the lab proves, what is hypothesis

This document separates **reproduced fact** from **analysis**. It does not
promise a "shell in 30 seconds": what exists here is a real, reproducible and
instrumented memory-corruption primitive, plus an honest discussion of what is
still missing to turn it into code execution.

Author: **eduxcode** — <https://github.com/eduxcode>

---

## 1. What is already proven

Running `./scripts/rce-evidence.sh` (target built with AddressSanitizer), the
whole CVE-2026-123007 chain ends like this:

```text
=================================================================
==197362==ERROR: AddressSanitizer: negative-size-param: (size=-1073741824)
    #0 ... in memcpy
    #1 ... in ngx_ssl_send_chain src/event/ngx_event_openssl.c:3150
    #2 ... in ngx_http_v2_send_output_queue src/http/v2/ngx_http_v2.c:557
    #3 ... in ngx_http_v2_write_handler src/http/v2/ngx_http_v2.c:502
    #4 ... in ngx_epoll_process_events src/event/modules/ngx_epoll_module.c:930
    ...
0x... is located 0 bytes inside of 1048576-byte region
allocated by thread T0 here:
    #1 ... in ngx_alloc src/os/unix/ngx_alloc.c:22
    #2 ... in ngx_palloc_large src/core/ngx_palloc.c:220
    #4 ... in ngx_output_chain_get_buf src/core/ngx_output_chain.c:484
    ...
SUMMARY: AddressSanitizer: negative-size-param
         src/event/ngx_event_openssl.c:3150 in ngx_ssl_send_chain
==197362==ABORTING
```

Three important facts in this report:

1. **Bug class**: `negative-size-param`. Not a null pointer, not a
   *use-after-free*. It is a `memcpy` whose third argument is a negative
   `ssize_t` that, converted to `size_t`, becomes ~`2^64`.
2. **Attacker-controlled length**: the value `-1073741824` is exactly the
   `send_window` the client made nginx accumulate (`2^64 − 1 GiB`). Changing
   the accumulated value changes `size`. The attacker decides *how much* the
   `memcpy` tries to copy.
3. **Source and destination**: the address ASAN points at is the 1 MiB
   *source buffer*, allocated by `ngx_output_chain_get_buf` — the response
   chunk created by `output_buffers 8 1m`. The destination is `c->ssl->buf`,
   the TLS write buffer (16 KiB by default, `ssl_buffer_size`).

Without ASAN, the same path ends in `SIGSEGV` inside `ngx_memcpy` (see
`scripts/verify.sh`), with `worker process ... exited on signal 11`.

---

## 2. Why this is corruption, not just DoS

A `memcpy(dst, src, (size_t)-N)` copies **everything mapped** between `dst` and
the first unmapped address, and also reads everything after `src`. That is:

```
        dst (SSL buf, 16 KiB)                src (1 MiB chunk)
             │                                    │
   ┌─────────▼──────────┬──────────────┬──────────▼──────┬───────────┬──────
   │ TLS buffer         │ adjacent heap │ response        │ heap      │ ...
   └────────────────────┴──────────────┴─────────────────┴───────────┴──────
             └────────── copy grows to the right ──────────▶
```

* **Bytes written past `dst`**: the worker heap — pools, connection/stream
  structs, buffers, glibc allocation headers.
* **Bytes read past `src`**: whatever is adjacent to the response chunk. If the
  attacker can place controlled data there (a request body, for example), the
  overflow writes **bytes of their choosing**.
* The copy only stops when it hits an unmapped (or read-only) page. Then the
  worker dies.

This is exactly the definition of a *heap buffer overflow* with
attacker-influenced content and length — the raw material of an exploit.

What ASAN shows is the instant of the first byte outside the allocation.
Without ASAN, glibc's `memcpy` (AVX2/AVX-512/ERMS) advances in 32–64 byte
blocks and only fails on the next unmapped page; depending on the heap, that can
mean several MiB written before the `SIGSEGV`.

---

## 3. The arithmetic of `size`

The value is not random. It originates in `ngx_http_v2_send_chain()`:

```c
if (limit == 0 || limit > (off_t) h2c->send_window) {
    limit = h2c->send_window;      /* size_t > 2^63 → negative off_t */
}
```

and arrives in `ngx_ssl_send_chain()`:

```c
send = buf->last - buf->pos;       /* >= 0 */
...
size = in->buf->last - in->buf->pos;

if (size > buf->end - buf->last) {
    size = buf->end - buf->last;
}

if (send + size > limit) {
    size = (ssize_t) (limit - send);   /* becomes negative */
}

ngx_memcpy(buf->last, in->buf->pos, size);   /* size_t ≈ 2^64 */
```

Since `send >= 0` and `limit < 0`, the condition `send + size > limit` is always
true and `size` takes the negative `limit`. There is no later clamp. This is the
point of no return.

---

## 4. The path to `2^63`: why ~52 GiB

For `(off_t) send_window` to become negative, the counter must pass `2^63`. Each
`WINDOW_UPDATE` adds at most `2^31 − 1`:

```
2^63 / (2^31 − 1) ≈ 4.29 × 10^9 frames
4.29 × 10^9 × 13 bytes ≈ 55.8 × 10^9 bytes ≈ 52 GiB
```

Close to `2^64`, it is ~104 GiB. Adding nginx's anti-abuse check
(`h2c->total_bytes / 8 > h2c->payload_bytes + 1048576`) and the request body
needed to "pay for" the frames, public analyses report ~119 GiB of total
traffic.

That is why the lab has the **accelerator**: it replaces only that stretch (the
52 GiB end state of frames) and is announced on screen. Stages 1–6 remain real
nginx 1.31.8 behavior.

---

## 5. What is missing for real RCE

The primitive exists. Converting it into code execution is the hard part, and
the lab does **not** demonstrate it. Four real obstacles:

### 5.1 The `memcpy` cannot be interrupted

The corruption happens *inside* the `memcpy`, and the `SIGSEGV` kills the worker
at that very instant. Any struct corrupted in the worker's own heap dies with
it — there is no return path to "use" the overwritten pointer. This defeats the
naive idea of "overwrite a function pointer and wait for the call".

### 5.2 The length is fixed at ~2^64

There is no negative `send_window` value that produces a "small" copy: any
negative becomes ~`2^64` as a `size_t`. You cannot ask to "overflow just 64
bytes". An exploit has to live with a gigantic linear write that ends in a page
fault.

### 5.3 Content depends on the adjacent heap

The first 1 MiB copied comes from the legitimate response. After that, the
`memcpy` reads whatever follows the source chunk. To write a payload you need
*grooming*: make the allocator place controlled data immediately after the
response buffer (request body, upload, large headers) and place a useful target
immediately after the TLS buffer.

### 5.4 The target must survive the fault

Because the worker dies, the corrupted target has to be consumed:

* by **another** worker or the master, through shared memory
  (`ssl_session_cache shared:`, `limit_req`/`limit_conn` zones, in-memory
  `proxy_cache`);
* by a process that restarts and re-reads a corrupted file/mapping;
* or by a `SIGSEGV` handler — which nginx does not install.

None of these paths has been reproduced here. Public analyses describe RCE with
heap grooming and ~119 GiB; in this lab we stop at the primitive, which is what
can be proven reproducibly in seconds.

---

## 6. Experiments still worth doing

If you want to continue the research (in an isolated environment):

1. **Measure the write window**: run without ASAN under `gdb`, capture the fault
   address and compare it with `dst`. This gives how many bytes were actually
   written before death.
2. **Destination grooming**: repeatedly allocate/free 1 MiB buffers
   (`output_buffers`) to try to place an interesting object (e.g.
   `ngx_pool_cleanup_t`, a stream struct) right after the SSL buffer.
3. **Source grooming**: send a request body with a recognizable pattern and check
   in the core dump whether it shows up in the copied stream.
4. **Shared memory**: map shared zones and see whether the overflow reaches one;
   measure whether the corruption survives the worker.
5. **h2c variant (no TLS)**: the path is different (`ngx_writev_chain`), probably
   just `EFAULT`; useful to compare primitives.

Each of these experiments needs its own instrumentation and must be clearly
separated from "original nginx behavior".

---

## 7. How to reproduce the current evidence

```bash
cd nginx2root-lab
./scripts/rce-evidence.sh          # ASAN build + attack + report
```

The first build takes 1–2 minutes; afterwards it is instant. The port used is
8444 (change it with `N2R_ASAN_PORT=...`).

To see the "pure" `SIGSEGV`, without ASAN:

```bash
# terminal 1
N2R_SINGLE=1 ./scripts/native-up.sh
# terminal 2
./scripts/native-attack.sh
```

---

## 8. Defensive reading

* The vector is **remote and unauthenticated**, but the traffic cost is high
  (~52 GiB to reach `2^63`, ~119 GiB for the full scenario).
* The guaranteed effect is **denial of service** (worker killed, connection
  dropped). Any RCE is conditional on grooming and on a target that survives the
  fault.
* The fix (1.31.9 / 1.30.7) eliminates the entire primitive; this is not a case
  of "just mitigating the crash".
* Until you upgrade: `http2 off;` removes this vector and CVE-2026-123633, but
  not the other use-after-free bugs from the same release.
