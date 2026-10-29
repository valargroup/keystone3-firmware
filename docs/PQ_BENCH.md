# Hash-based signature benchmark

Debug and simulator builds include a benchmark that times key generation, signing and
verification of hash-based signatures on the device:

| Name | Scheme | Library |
|---|---|---|
| `SLH-128s`, `SLH-128f`, `SLH-192s`, `SLH-192f`, `SLH-256s` | SLH-DSA (FIPS 205) SHA2 parameter sets | `slh-dsa` |
| `lean h22 b12`, `lean h22 layer`, `lean h28 b12`, `lean h28 layer` | leanSphincs over SHA-256 as [sphincs.art](https://sphincs.art/) shows it for a hardware wallet at its lowest and highest lifetimes, 2^26 signatures (tree height 22) and 2^32 (height 28): "Pruning" with a kept subtree of 2^12 leaves (107K and 137K signatures), and "Uniform", a three-layer hypertree (82M and 5.6B signatures) | `sphincs` from TomWambsgans/sphincs.art |

Every run derives keys from fixed seeds and signs a fixed message, so runs repeat exactly. Each
signature is verified; a failure is reported as an error, not as a time. Production builds do
not contain the benchmark.

The `slh-dsa` dependency is 0.0.3 plus the SHA-2 seed-state caching from 0.2
(`valargroup/signatures`, branch `roman/mac/claude/slh-dsa-0.0.3-seed-cache`). This workspace
cannot use 0.2 itself, because `zcash_primitives` pins the RustCrypto 0.11 pre-releases. Its
signatures are byte-identical to 0.2.0-rc.5, and signing costs the same with software SHA-256.

The `sphincs` dependency is TomWambsgans/sphincs.art at `f181496`, the commit zakura-core/zakura#1796
uses, plus a change that lets it build without std (`valargroup/sphincs.art`, branch
`roman/mac/claude/no-std-keystone`). Its keys and signatures are byte-identical to `f181496`.

## Running it

- **Device screen**: Settings → About → PQ Bench. Each scheme has its own Run button, which runs
  one round of that scheme (one key generation, signature and verification); its row then shows
  the times. Press it again for another round. While it works, the row shows the
  step running now. Results of every scheme stay on screen, and in flash, until it runs again.
- **UART** (debug builds, UART0 at 512000 baud): send `#pq bench:all` followed by CR LF, or
  a scheme name or index in place of `all`. An iteration count after the name runs that many rounds and reports their median (the
  default is one); `#pq bench:` with
  no arguments lists the schemes. A `pqbench,step,...` line comes before every step. Results are CSV
  lines starting with `pqbench,`, with median, minimum and maximum microseconds per operation,
  then the signature and public key sizes in bytes. The last lines report the benchmark task's
  unused stack and the lowest free heap seen.
- **Simulator**: `PQ_BENCH="all 3" ./build/simulator` prints the same CSV and exits without
  opening a window. Simulator times measure the host computer, not the device.

**If the device resets.** Before every step the device saves which scheme, step and iteration it
is on, plus every scheme's latest results, to a sector of SPI flash. After a reset, open PQ Bench:
the top line says which scheme was running, its row says "CRASHED: reset during <step>,
iteration i of n", and the other rows keep their results. The UART prints
`pqbench,last_run_reset_during,...` the first time the record is read.

On the device the benchmark runs on its own task, below every other task but the idle task.
`slh-dsa` builds each signature on the stack and copies it several times, so the large SLH-DSA
sets need up to about 200 KB of stack (`SLH-192f`), and leanSphincs about 230 KB of heap for its
key's trees. The SRAM heap has less than either free, so the task's 240 KB stack lives in PSRAM,
allocated on the first run and kept, and the Rust allocations the task makes go to PSRAM too. Stack accesses may be slower than from SRAM, so
compare device times with that in mind. Times come from the 1 ms OS tick plus the SysTick
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
