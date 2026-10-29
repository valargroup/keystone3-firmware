# Hash-based signature benchmark

Debug and simulator builds include a benchmark that times key generation, signing and
verification of hash-based signatures on the device:

| Name | Scheme | Library |
|---|---|---|
| `SHA-256 block` | Not a signature: 10,000 SHA-256 compressions of one 64-byte block, shown as the time per block. Every scheme here spends nearly all its time hashing, so this is the device's hashing speed on its own | `sha2`, as `slh-dsa` and 192-bit leanSphincs use it |
| `SHA-512 block` | 10,000 SHA-512 compressions of one 128-byte block; 192-bit leanSphincs uses SHA-512 for its multi-node hashes and encodings | `sha2` |
| `SLH-128s`, `SLH-128f`, `SLH-192s`, `SLH-192f`, `SLH-256s` | SLH-DSA (FIPS 205) SHA2 parameter sets | `slh-dsa` |
| `lean192 h22 b12`, `lean192 h22 layer`, `lean192 h28 b12`, `lean192 h28 layer` | The experimental 192-bit leanSphincs family over SHA2 (SHA-256 for chain steps, SHA-512 for multi-node hashes) with FORS, sphincs.art's defaults for that family, at its lowest and highest lifetimes, 2^26 signatures (tree height 22) and 2^32 (height 28): "Pruning" with a kept subtree of 2^12 leaves and "Uniform", a three-layer hypertree. Its security is not proved; see sphincs.art | `sphincs::level192` from valargroup/sphincs.art |

Every run derives keys from fixed seeds and signs a fixed message, so runs repeat exactly. Each
signature is verified; a failure is reported as an error, not as a time. Production builds do
not contain the benchmark.

The `slh-dsa` dependency is 0.0.3 plus the SHA-2 seed-state caching from 0.2
(`valargroup/signatures`, branch `roman/mac/claude/slh-dsa-0.0.3-seed-cache`). This workspace
cannot use 0.2 itself, because `zcash_primitives` pins the RustCrypto 0.11 pre-releases. Its
signatures are byte-identical to 0.2.0-rc.5, and signing costs the same with software SHA-256.
The branch also adds `try_sign_with_context_into`, which signs into a signature the caller
owns; the benchmark keeps that signature on the heap, so it never passes through the stack.

The `sphincs` dependency is valargroup/sphincs.art branch `roman/mac/claude/no-std-keystone-192`:
the experimental 192-bit family from branch `roman/mac/codex/192-bit-configurations`, plus changes
that let it build without std and use the RustCrypto 0.10 releases of `sha2`, `sha3` and `hmac`
instead of 0.11, which this workspace cannot link. Its signatures match the family's
known-answer vectors.

## Running it

- **Device screen**: Settings → About → PQ Bench. Each scheme has its own Run button, which runs
  one round of that scheme (one key generation, signature and verification); its row then shows
  the times, with a grey line saying how that run was set up. Press it again for another round.
  While it works, the row shows the step running now. Results of every scheme stay on screen, and
  in flash, until it runs again. Two toggles at the top set up the next run:
  - **Stack: on-chip / PSRAM** puts the benchmark's stack in on-chip RAM (64 KB, the default) or
    in external PSRAM (240 KB, as earlier builds did).
  - **Priority: low / high**. Low runs below every other task, so the screen stays live. High runs
    above the screen, USB and touch tasks (only the watchdog and UART command tasks are higher),
    so the screen freezes until the run ends.
- **UART** (debug builds, UART0 at 512000 baud): send `#pq bench:all` followed by CR LF, or
  a scheme index in place of `all`. An iteration count after it runs that many rounds and reports
  their median (the default is one); `psram` puts the stack in PSRAM and `high` runs at high
  priority, as in `#pq bench:2 1 psram high`; `#pq bench:` with
  no arguments lists the schemes. A `pqbench,step,...` line comes before every step. Results are CSV
  lines starting with `pqbench,`, with median, minimum and maximum microseconds per operation,
  then the signature and public key sizes in bytes. The last lines report the benchmark task's
  stack size and unused stack, and the lowest free heap seen.
- **Simulator**: `PQ_BENCH="all 3" ./build/simulator` prints the same CSV and exits without
  opening a window. Simulator times measure the host computer, not the device.

**If the device resets.** Before every step the device saves which scheme, step and iteration it
is on, plus every scheme's latest results, to a sector of SPI flash. After a reset, open PQ Bench:
the top line says which scheme was running, its row says "CRASHED: reset during <step>"
(with "iteration i of n" when it ran several), and the other rows keep their results. The UART prints
`pqbench,last_run_reset_during,...` the first time the record is read.

On the device the benchmark runs on its own task, one for each stack placement, each created on
its first run and kept. With signatures on the heap, the deepest scheme uses about 34 KB of stack
on a Mac (192-bit leanSphincs), so the 64 KB on-chip stack has about twice that;
`cargo run --release -p app_pq_bench --example stack_need` measures it again. leanSphincs keeps
its key's trees on the heap, more than the on-chip heap has free, so the Rust allocations the
benchmark makes always go to PSRAM. Times come from the 1 ms OS tick plus the SysTick
countdown within the current tick, which resolves well under a microsecond. The CPU cycle counter
does not run on this chip, so earlier builds showed 0us for every step shorter than 10 s; a run now
refuses to start if the timer is not advancing.

## Measuring on a ForgeBox

A retail Keystone 3 only boots firmware signed by Keystone. A ForgeBox boots firmware signed
with a key you register on it once.

1. Install the CLI (`npm install -g forgebox-cli`) and check that `forgebox status` sees the
   device.
2. Run `forgebox keygen`, and back up both `.pem` files offline before the next step. Then run
   `forgebox register ~/.forgebox/keys` and confirm the fingerprint on the device. The device
   accepts one key registration, ever.
3. Build a debug firmware: `python3 build.py` without `-e production`, or configure CMake with
   `-DLIB_RUST_C=ON -DRU_SUPPORT=true` and no `BUILD_PRODUCTION`. This produces
   `build/mh1903_full.bin`.
4. Sign it: `forgebox sign --s build/mh1903_full.bin --d build/forgebox.bin --key ~/.forgebox/keys/private.pem`.
   Copy `forgebox.bin` to an SD card and run the firmware upgrade on the device. If it fails to
   boot, hold the power button for six seconds to enter recovery mode and load another image.
   Keystone does not support this firmware as a drop-in ForgeBox image, so this first flash is
   the risky step.
5. Keep the device on USB power with the screen on, then run the benchmark from the screen or
   over UART. Each Run is one round; for steadier numbers press it a few times and note each
   result.
