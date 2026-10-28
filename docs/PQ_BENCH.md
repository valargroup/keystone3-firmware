# Hash-based signature benchmark

Debug and simulator builds include a benchmark that times key generation, signing and
verification of hash-based signatures on the device:

| Name | Scheme | Library |
|---|---|---|
| `WOTS+` | RFC 8391 WOTS+, n=32, w=16, SHA-256 | `pq-crypto` |
| `FORS-256f`, `FORS-256s`, `FORS-192f`, `FORS-192s`, `FORS-128s` | FIPS 205 FORS with the trees, height and hash length of that SLH-DSA-SHA2 set (35×9, 22×14, 33×8, 17×14, 14×12) | `pq-crypto` (prototype) |
| `FORS-16x16` | FORS with 16 trees of height 16 and 32-byte hashes, used by no SLH-DSA set | `pq-crypto` (prototype) |
| `SLH-128s`, `SLH-128f`, `SLH-192s`, `SLH-192f`, `SLH-256s` | SLH-DSA (FIPS 205) SHA2 parameter sets | `slh-dsa` |

Every run derives keys from fixed seeds and signs a fixed message, so runs repeat exactly. Each
signature is verified; a failure is reported as an error, not as a time. Production builds do
not contain the benchmark.

The `slh-dsa` dependency is 0.0.3 plus the SHA-2 seed-state caching from 0.2
(`valargroup/signatures`, branch `roman/mac/claude/slh-dsa-0.0.3-seed-cache`). This workspace
cannot use 0.2 itself, because `zcash_primitives` pins the RustCrypto 0.11 pre-releases. Its
signatures are byte-identical to 0.2.0-rc.5, and signing costs the same with software SHA-256.

## Running it

- **Device screen**: Settings → About → PQ Bench → Run. It runs every scheme three times and
  shows the median times.
- **UART** (debug builds, UART0 at 512000 baud): send `#pq bench:all 10` followed by CR LF,
  or a scheme name or index in place of `all`. The iteration count is optional; `#pq bench:`
  with no arguments lists the schemes. Results are CSV lines starting with `pqbench,`, with
  median, minimum and maximum microseconds per operation, then the signature and public key
  sizes in bytes. The last lines report the benchmark task's unused stack and the lowest free
  heap seen.
- **Simulator**: `PQ_BENCH="all 5" ./build/simulator` prints the same CSV and exits without
  opening a window. Simulator times measure the host computer, not the device.

On the device the benchmark runs on its own task with a 128 KB stack at below-normal priority.
Times come from the CPU cycle counter (204 MHz), or from the 1 ms tick for steps longer than 10 s.

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
   over UART. Repeat it three times and report the median of the three runs.
