# Pico 2 / RP2350 Bitcoin miner — hardware SHA-256
Optimized dual-core bitcoin miner (firmware) for Pico2 MCU to be used with btcminer-mcu project. Achieves 342kH/s (core-0, hardware SHA-256) + 31kH/s (core-1 software SHA-256). Up to 1.3 Mhash/s on overclocked Pico2. 

Real double-SHA256 mining on the RP2350's on-chip SHA-256 accelerator
(`SHA256_BASE = 0x400f8000`). It validates itself against known answer vectors
before it will mine, benchmarks itself, and can re-mine real historical Bitcoin
blocks to prove the work is genuine.

The code was initialy produced by Claude Opus 5 model guided by @petrs, then human-verified on the real Pico2 devices for functionality including mining real blocks on `bitcoind --regtest`. If you are curious how almost fully autonomous agentic optimization on physical device look like, check related [pico2_miner_codex](https://github.com/mcubench/exp_pico2_miner_codex/perf_progress.md) project which performed 100+ optimization campains on real  Pico 2 RP2350 device. 


## Usage

```
git clone https://github.com/mcubench/pico2-btcminer.git
```

> **Board note.** This was developed on a Feitian RP2350A USB token: QFN-60,
> **2 MiB** of flash, Pico 2 reference design, LED on GP25, button on `QSPI_SS`.
> The build declares `PICO_FLASH_SIZE_BYTES 2097152` because the `pico2` board
> header claims 4 MiB and addresses past the end of a smaller die *alias silently*
> onto the vector table instead of faulting. Change it if your board differs.


1. Hold **BOOTSEL** on the Pico 2, plug in USB, release. A drive called
   `RP2350` appears.
2. Copy one of the `.uf2` files from `/artifacts` folder onto it (start with `pico2_btc_miner_riscv.uf2`). The board reboots automatically.
3. Open the USB serial port at any baud rate:

```
# Linux
screen /dev/ttyACM0 115200          # or: minicom -D /dev/ttyACM0

# macOS
screen /dev/tty.usbmodem* 115200

# Windows
# PuTTY / Tera Term on the new COM port 
```

It runs the self test and benchmark automatically on boot, then shows a menu.
Serial also comes out of UART0 (GP0 = TX, GP1 = RX) at 115200 if you prefer.

## Six binaries: Arm and RISC-V, interactive / protocol / overclocked protocol

RP2350 contains two Cortex-M33 cores *and* two Hazard3 RISC-V cores. Only one
architecture runs at a time, chosen by the image you flash — the bootrom reads
the image type and switches. The SHA-256 engine is shared between them, so this
is a clean A/B: same peripheral, same clock, different core driving the bus.

| file | core | boots into | clock | hashrate |
|---|---|---|---|---:|
| `pico2_btc_miner_riscv.uf2` | Hazard3 | interactive menu | 150 MHz | — |
| `pico2_btc_miner_arm.uf2` | Cortex-M33 | interactive menu | 150 MHz | — |
| `pico2_btc_miner_riscv_PROTOCOL.uf2` | Hazard3 | protocol | **stock 150 MHz** | 332.6 kH/s |
| `pico2_btc_miner_arm_PROTOCOL.uf2` | Cortex-M33 | protocol | **stock 150 MHz** | 323.3 kH/s |
| `pico2_btc_miner_riscv_PROTOCOL_OVERCLOCKED_472MHz_1v50.uf2` | Hazard3 | protocol | 472 MHz @ 1.50 V | 1.047 MH/s |
| `pico2_btc_miner_arm_PROTOCOL_OVERCLOCKED_472MHz_1v50.uf2` | Cortex-M33 | protocol | 472 MHz @ 1.50 V | 1.017 MH/s |

The plain `_PROTOCOL` images touch **neither clock nor voltage** — they run at the
boot default and are safe to leave running indefinitely. The
`_PROTOCOL_OVERCLOCKED_` images name their clock and core voltage in the filename
because you cannot tell from a running board which one you flashed. They are
3.15x faster and run the die 36% over nominal voltage.

UF2 family is `rp2350-riscv` or `rp2350-arm-s` respectively; the bootrom rejects
the wrong one rather than running it.

The **interactive** images are for benchmarking and exploration: self test,
benchmark, clock and voltage control, the automatic sweep, and `p` to enter
protocol mode by hand. The **protocol** images validate the engine at whatever
clock they will mine at, then go straight to serving work. The overclocked ones
apply clock and voltage first with no prompt, and fall back to 150 MHz if the self
test fails there; either kind refuses to mine at all if the self test fails at
stock. Protocol mode leaves core 1 idle deliberately: a second worker
on a different nonce range would corrupt the host's hash-rate measurement.

Both architectures print which core they are running on at boot. Flash one, note
the benchmark, flash the other, compare. Switching back is just another BOOTSEL
drag — the bootrom is architecture-independent, so you can never brick yourself
into one mode.


### Mining real bitcoins - usage with btcminer-mcu

To start mining on real bitcoin network, download [Bitcoin core](https://bitcoin.org/en/bitcoin-core/) (tested with bitcoin-22.0.0) and [btcminer-mcu](https://github.com/mcubench/btcminer-mcu) project, upload `*_PROTOCOL_*.u2f` firmware to your Pico 2 / RP2350 and follow the instructions from [btcminer-mcu](https://github.com/mcubench/btcminer-mcu/blob/master/README.md) for `bitcoind --regtest`.

However, unless you are insanely lucky, you will not find any block on mainet and your energy per TH (well MH in this case) does not make any economical sense :). 


## Menu

| key | action |
|-----|--------|
| `t` | self test — NIST vectors, real block headers, randomised HW-vs-SW fuzz |
| `b` | benchmark — CPU-fed vs DMA-fed vs software |
| `g` | re-mine block 0 (genesis) |
| `h` | re-mine block 125552 |
| `m` | mine continuously, 24 leading zero bits |
| `M` | mine continuously, 28 leading zero bits |
| `s` | stability stress test at the current clock (30 s, validates continuously) |
| `a` | auto clock sweep: validate, stress and benchmark at every clock step |
| `1`/`q` … `4`/`r` | 150 / 200 / 250 / 300 MHz |
| `5`/`u` … `0`/`k` | 400 / 420 / 440 / 460 / 480 / 500 MHz (20 MHz steps) |
| `V` | allow core voltage above 1.30 V (off by default, needs confirmation) |
| `+` / `-` | raise / lower core voltage one step, held across clock changes |
| `c` | set any clock by typing MHz |
| `d` | toggle the core 1 software miner |
| `T` | ADC / temperature sensor diagnostic |

Letter aliases exist because some terminals run the numeric keypad in
application mode and send `ESC O x` instead of a digit. If that happens the
firmware says so and names the bytes it received. CR/LF from line-buffered
terminals is ignored.


## Measured results

Both binaries, same board, stock 150 MHz. One Bitcoin hash = 3 SHA-256
compressions on this chip (no midstate caching -- see below).

| Core | Mode | Hash rate | Cycles/hash | Bus cyc/txn | vs software |
|---|---|---:|---:|---:|---:|
| Hazard3 | DMA | **332,594 H/s** | 451.0 | 4.84 | 25.0x |
| M33 | DMA | 323,275 | 464.0 | 5.07 | 21.8x |
| Hazard3 | CPU fast | 317,125 | 473 | 5.21 | 23.8x |
| M33 | CPU fast | 309,917 | 484 | 5.40 | 20.9x |
| M33 | CPU safe | 168,729 | 889 | 6.77 | 11.4x |
| Hazard3 | CPU safe | 166,482 | 901 | 6.89 | 12.5x |
| M33 | software | 14,812 | 10,127 | - | 1.0x |
| Hazard3 | software | 13,318 | 11,263 | - | 1.0x |

All three feed modes passed the self test on both architectures, so the fast
path's assumption -- that the 16th `WDATA` write lands before the following
`CSR` read -- holds on both an Arm and a RISC-V core.

**The bridge is the bottleneck, and it is not a CPU property.** Every hash needs
58 bus transactions (48 `WDATA` writes, 8 `SUM` reads, 2 `START` writes) on top
of 171 cycles of compression. Fitting that to the data gives a constant ~4.8-5.4
cycles per transaction across two unrelated cores. Swapping the entire
instruction set moves the hardware paths by under 3%; it moves the software
baseline by 10%.

**Why CPU safe is half speed.** A store to a peripheral is posted -- the core
continues. A load blocks until data returns. Safe mode reads `CSR` before every
word, turning 48 fire-and-forget writes into 48 stall-then-write pairs.

**Why DMA barely wins.** It does not widen the bridge; the 32 words still cross
one at a time. It only removes the polling granularity loss between blocks,
because `DREQ_SHA256` has no detection latency. That is worth ~3%, twice per
hash.

**Why the M33 wins in software.** Armv8-M folds rotates into the operand, so
`s1(x) = ror17 ^ ror19 ^ shr10` is three instructions. Hazard3 has Zbb `rori`
but no shifter operand, so each rotate is standalone: five instructions. Only
the Sigma/sigma functions benefit, which is why the gap is 10% and not more.

Scaling projection (**not measured**) -- both cores are bridge-bound and the
bridge runs from `clk_sys`, so cycles/hash should hold:

| Config | 150 MHz | 200 MHz | 250 MHz | 300 MHz |
|---|---:|---:|---:|---:|
| Hazard3 DMA | 332k (measured) | 442k | 553k | 664k |
| M33 DMA | 323k (measured) | 430k | 538k | 645k |


## Overclocking

Stock is 150 MHz at 1.10 V. The firmware offers 200, 250, 300, 400, 450 and
500 MHz, raising core voltage with frequency: 1.15 V at 200, 1.20 V at 300,
1.30 V from 400 up.

Every step has an exact PLL solution off the 12 MHz crystal. **350 MHz does
not** and is deliberately absent -- 350x2 = 700 MHz is below the 750 MHz VCO
minimum, and 350x3 = 1050 is not a multiple of 12, so `set_sys_clock_khz`
refuses it outright.

1.30 V is `VREG_VOLTAGE_MAX`. `V` unlocks 1.35 V (450 MHz) and 1.40 V
(500 MHz) after an explicit confirmation; it is off by default. That path calls
`vreg_disable_voltage_limit()`, which the SDK describes as beyond the safe
range of operation. The register encoding goes to 3.30 V -- this firmware caps
at 1.40 V and will not go near that.

Above 400 MHz the peripheral clock is re-pointed at the USB PLL (48 MHz)
instead of following `clk_sys`, since a 500 MHz `clk_peri` is far outside UART
specification. The console is unaffected by the overclock either way.

Three separate risks, worth keeping apart:

- **Damage.** Low and gradual up to 1.30 V. Higher voltage accelerates ageing
  rather than causing sudden failure.
- **Instability.** Loud and harmless. No clock setting is persisted, so a power
  cycle always returns to 150 MHz, and BOOTSEL lives in the bootrom and always
  works. You cannot brick the board this way.
- **Silent miscomputation.** The real hazard. A marginal SHA engine does not
  crash -- it returns wrong hashes at full speed and looks perfectly healthy.

The third is what the firmware guards against. `s` mines while re-checking a
known block hash continuously; `a` steps the clock up and, at every step,
validates all vectors, stresses for 4 s with continuous known-answer checks,
then runs the full benchmark -- printing a scaling table of hash rate per feed
mode per clock. It settles one step below the first failure. A sweep takes
roughly 40 seconds. The mining loop
itself re-verifies a known vector every 20,000 hashes and drops back to 150 MHz
if the engine ever stops reproducing it. Overhead is about 0.005%.

Timing margin shrinks as the die warms, so a clock that validates cold can start
corrupting minutes later. That is why the checks are continuous rather than a
one-off at startup. Die temperature is shown in the prompt and in the stress
output.

**Measured scaling**, DMA mode, both cores on the same die at 1.30 V max:

| MHz | Hazard3 | cyc/hash | Cortex-M33 | cyc/hash |
|---|---:|---:|---:|---:|
| 150 | 332,600 | 451.0 | 323,275 | 464.0 |
| 200 | 443,500 | 451.0 | 431,033 | 464.0 |
| 250 | 554,300 | 451.0 | 538,793 | 464.0 |
| 300 | 665,200 | 451.0 | 646,550 | 464.0 |
| 400 | 886,900 | 451.0 | 862,069 | 464.0 |
| 420 | 931,300 | 451.0 | 905,174 | 464.0 |
| 440 | 975,600 | 451.0 | failed | - |
| 450 | hung | - | - | - |

At 1.30 V both cores stop: Hazard3 at 440 MHz (450 hangs), the M33 at 420 MHz
(440 fails detectably). Crossing a megahash needs 452 MHz, since 451 cycles/hash
at 451 MHz is exactly 1.000 MH/s.

### Maximum achieved

Unlocking voltage with `V` raises the ceiling considerably. Every figure below is
a measured sweep result on one die, validated against known block hashes at each
step.

| Voltage | Hazard3 ceiling | rate | M33 ceiling | rate |
|---|---|---:|---|---:|
| 1.30 V (SDK max) | 440 MHz | 975.6 kH/s | 420 MHz | 905.2 kH/s |
| 1.35 V | 460 MHz | 1.020 MH/s | — | — |
| 1.40 V | 492 MHz | 1.091 MH/s | — | — |
| 1.50 V | 534 MHz | 1.184 MH/s | 488 MHz | 1.052 MH/s |
| 1.60 V | **570 MHz** | **1.258 MH/s** | — | — |

**Peak of the project: 552 MHz dual core at 1.60 V = 1.266 MH/s**, hardware
accelerator plus the software worker on core 1 — 3.81x stock, and 0.6% above the
single-core record. Confirmed by back-to-back sweeps in one session:

| configuration | last stable | rate | fails at |
|---|---|---:|---|
| single core | 570 MHz | 1.258 MH/s | 576 MHz |
| **dual core** | **552 MHz** | **1.266 MH/s** | 558 MHz |

Dual core only overtook single core after core 1's launch was deferred until
after the clock transition completes and boot telemetry is flushed: the
inter-core FIFO handshake, not the datapath, had been the limiter. That moved the
dual-core ceiling from 546 to 552 MHz and changed how it fails — from "core 1
stops launching while hashing still validates" to the same USB disconnect that
ends the single-core sweep at 576 MHz.

**Cycles per hash stayed flat at 451.0-453.1 across the whole 150-570 MHz range**,
a 3.8x span. Nothing degrades gracefully approaching the wall: the datapath is
fully correct at 570 MHz and the part simply stops at 576.

The M33 walls about 20 MHz lower than Hazard3 and needs roughly 0.10 V more for
the same clock — longer critical paths in the bigger pipeline. Hardware hash rate
differs by under 3% between the two, because the APB bridge, not the CPU, sets it.

1.60 V is 45% over the 1.10 V nominal and ages the die; treat it as a benchmark
peak, not a setting to leave running. For sustained use the shipped protocol
firmware runs **472 MHz at 1.50 V = 1.047 MH/s**, which is 62 MHz (11.6%) below
the measured 1.50 V ceiling.

Marginal clocks survive many seconds of load — 492 and 500 MHz each passed
validation, the full soak *and* the entire benchmark before dying — so the sweep
soaks for 15 s at 460 MHz and above, and even that only validates to about 17 s of
sustained load.

### Temperature sensor: hardware, not software

On the board this was developed against, every ADC conversion sets
`ADC_CS_ERR` and returns 0xFFF, so die temperature shows as `n/a`. A standalone
probe (`adc-probe/`) tested every hypothesis:

- all nine channels, including the internal temperature diode
- `clk_adc` from PLL_USB 48 MHz, XOSC 12 MHz and PLL_SYS
- SDK path, hand-rolled register path, and the FIFO path with `err_in_fifo`
- ten repeated conversions, and a 200 ms settle after `TS_EN`

Every combination returned exactly 4095 with `ERR=1`, never varying. The ADC's
digital side is alive -- `CS` reads and writes work, `READY` asserts, the FIFO
fills -- but no conversion is valid. Since the *internal* diode needs no
external pin, this points at the analog supply (`ADC_AVDD`) rather than any
software setting. There is no software fix.

Two things the probe did settle:

- **Package matters.** `SYSINFO_PACKAGE_SEL` reports QFN-60 vs QFN-80, and the
  temperature sensor is on channel 4 or channel 8 accordingly. This firmware
  now reads that register at runtime instead of guessing at compile time --
  `ADC_TEMPERATURE_CHANNEL_NUM` is unreliable because it derives from
  `NUM_ADC_CHANNELS`, chosen by `#if PICO_RP2350A` inside `platform_defs.h`,
  which includes nothing and may be evaluated before the board header.
- **`clk_adc` is enabled at boot**, despite `CLOCKS_CLK_ADC_CTRL_ENABLE_RESET`
  being 0. The firmware still pins it to 48 MHz, but defensively, not as a fix.

Also worth knowing: reading GPIO pins without `adc_gpio_init()` is not a valid
control, since those pads keep their digital buffers and pulls and RP2350 pads
with a pull-down can latch high.

Nothing else depends on this -- temperature is only ever displayed, never used
in any decision.

A hang cannot trigger the sweep's voltage retry, because the retry needs a
failure the firmware can observe. Use `+` to raise voltage **before** selecting
a higher clock.

Cycles per hash is flat to four significant figures across a 2.9x clock range
on both cores: the APB bridge scales exactly with `clk_sys`, so clock is a pure
multiplier.

**The frequency ceiling belongs to the CPU core, not the accelerator.** Same
die, same peripheral, same bridge -- yet the M33 walls at 420 MHz while Hazard3
reaches 440. Hazard3's short 3-stage pipeline has shorter critical paths. Note
also the difference in how they fail: the M33 failed detectably at 440 and the
stress check caught it, while Hazard3 hung outright at 460.

Hazard3's 7.8% overall lead is 2.9% from cycles/hash times 4.8% from clock
headroom. The M33 wins software by 11% (10,127 vs 11,263 cycles/hash) on the
strength of its shifter operand. Silicon varies -- use `a` rather than copying
these numbers.

`1` is stock. `2`–`4` raise core voltage and overclock; that is at your own
risk, though the firmware runs entirely from SRAM (`copy_to_ram`) so flash
timing is not a factor.

## What "validates against known vectors" means here

The firmware refuses to trust the engine until it has checked it:

- **11 NIST/RFC SHA-256 vectors** across every padding edge case (55, 56, 63,
  64, 119, 120, 128 bytes), plus the one-million-`a` vector streamed straight
  through the engine.
- **Three real Bitcoin block headers** — blocks 0, 1 and 125552 — hashed with
  all three feed modes and checked against their published block hashes. It
  also confirms each hash actually satisfies that block's own difficulty
  target.
- **512 randomised headers** cross-checked against an independent software
  SHA-256 running on the same chip.

If a feed mode fails, it is disabled for the rest of the session and mining
falls back to a slower but more conservative one.

## Re-mining a real block

`g` and `5` fix every header field except the nonce, start 200 000 below the
answer, and search forward for a nonce that beats the block's target. Both
windows were checked to contain exactly one solution, so the miner must land on
the historical nonce — 2083236893 for genesis, 2504433986 for block 125552 —
and reproduce the published hash exactly. That is the proof it is doing real
proof-of-work rather than replaying a stored answer.

## The interesting hardware detail

A Bitcoin hash is normally 2 SHA-256 compressions, not 3: the first 64 bytes of
the header never change while you roll the nonce, so miners compute that block
once and cache the resulting "midstate".

**You cannot do that on RP2350.** `CSR.START` always reloads the standard
SHA-256 IV and the `SUM` registers are read-only, so there is no way to load a
midstate back in. Every nonce costs the full 3 compressions. That is a hard
~33% throughput loss versus any implementation that can checkpoint, and it is
inherent to the silicon, not to this code.

What the code does optimise:

- Header bytes are byte-swapped into big-endian message words **once per work
  item**, and `BSWAP` is left off, so the per-nonce cost is one `REV`.
- The 16 words of a block are written back to back. The datasheet guarantees
  `WDATA_RDY` only drops *after* the 16th word ("goes low for 57 cycles whilst
  the core completes its digest"), so a ready-poll is only needed between
  blocks.
- Fast rejection on a single word: Bitcoin reads the digest as a little-endian
  integer, so the most significant limb is `bswap32(H'7)`. One compare rejects
  almost every nonce without reading the other seven registers.
- DMA mode sends both header blocks as one 32-word transfer paced by
  `DREQ_SHA256`, so the inter-block wait costs no CPU cycles at all.

The engine's floor is 57 cycles per block, so 3 × 57 = 171 cycles per hash —
about 877 kH/s at stock 150 MHz. The benchmark reports what fraction of that
ceiling each feed mode actually reaches; the gap is bus overhead getting words
into `WDATA`. I could not measure this on real silicon, so the numbers your
board prints are the real answer.

## Honest expectations

At difficulty 1 (2009) a block would take on the order of hours. At block
125552's difficulty, years. At modern difficulty — above 1e14 — you are past
the age of the universe by a wide margin. This is a SHA-256 benchmark and a
hardware demo. It will not earn anything, and the firmware prints these numbers
itself so the point is unavoidable.

## What to expect from the RISC-V build

The engine is identical, so the 171 cycles of compression per hash are fixed.
What changes is everything around them: how fast the core gets 48 words across
the APB bridge, and how the software SHA-256 baseline compares.

Hazard3 has the Zbb bit-manipulation extension, so `__builtin_bswap32` becomes a
single `rev8` and `__builtin_clz` a single `clz` — the same one-instruction cost
as Arm's `rev` and `clz`. The hot loop compiles to the same shape: an unrolled
run of load/store pairs into `WDATA`.

Worth watching in the benchmark:

- **DMA mode should be nearly architecture-independent.** The DMA engine is the
  bus master; the core only arms it. If DMA differs much between the two
  builds, something other than the bus is dominating.
- **CPU fast mode is the real comparison** — it measures how well each core's
  store behaviour keeps the bridge fed.
- **CPU safe vs fast** shows whether Hazard3 pays the same penalty for blocking
  reads that the M33 does.
- **Software mode** is a pure core-vs-core benchmark with no peripheral
  involved: RV32IMAC_Zbb against Armv8-M Thumb-2.

The RISC-V binary is larger (about 66 KB vs 50 KB of text). That is normal —
Thumb-2 is denser than RV32IMAC, and the two builds use different C libraries.
It has no bearing on hash rate; both run entirely from SRAM.

## Using both cores

The SHA-256 engine cannot be shared. There is one instance, one state, and
`START` reloads the IV -- a second core issuing `START` mid-hash would destroy
the first core's work. Two cores would have to take a lock and hash in turn, so
the hardware path gains nothing.

What core 1 *can* do is run the pure-software path, which touches no peripheral
at all, over the top half of the nonce space. `d` toggles it. Expected gain is
single-digit percent: software runs at roughly 1/25th of the hardware rate.

Two effects work against it, which is why the benchmark measures rather than
assumes. Both cores share SRAM, so core 1's memory traffic can slow the
hardware path; and two busy cores run hotter, which at 1.30 V may cost a clock
step worth more than the gain. With `d` on, `b` reports hardware alone,
hardware with core 1 running, core 1's own rate, and the combined total, so the
contention cost is visible directly. Core 1 is held in reset when disabled.

Core 1 never prints -- stdio locking across cores invites deadlock. It
publishes counters and a share mailbox; core 0 does all reporting.

Mixed architecture (one M33 + one Hazard3) is possible in silicon -- `ARCHSEL`
has independent per-core bits -- but is not worth building. Both cores share
`clk_sys`, and the M33 tops out 20 MHz lower, so a mixed pair is capped at the
M33's ceiling and ends up slower than Hazard3 alone.

## Build from source

```bash
sudo apt install gcc-arm-none-eabi libnewlib-arm-none-eabi cmake ninja-build
git clone -b 2.1.1 --recurse-submodules https://github.com/raspberrypi/pico-sdk
export PICO_SDK_PATH=$PWD/pico-sdk

# Arm
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build            # -> build/pico2_btc_miner.uf2
```

SDK 2.1.1 needs `picotool` to produce the UF2; CMake will fetch and build it,
or point it at an existing install with `-Dpicotool_DIR=...`.

For RISC-V you need a `riscv32-unknown-elf` GCC targeting
`rv32imac_zicsr_zifencei_zba_zbb_zbs_zbkb`. If yours bundles newlib, this is all
you need:

```bash
cmake -S . -B build-riscv -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DPICO_PLATFORM=rp2350-riscv -DPICO_BOARD=pico2
cmake --build build-riscv
```

Ubuntu's `gcc-riscv64-unknown-elf` ships **no C library**, so this build was
made against picolibc instead. Two project options exist for that case, both
no-ops otherwise:

```bash
sudo apt install gcc-riscv64-unknown-elf picolibc-riscv64-unknown-elf
# the SDK looks for riscv32-unknown-elf-*, so alias the riscv64 driver
mkdir -p /opt/rv32bin
for t in gcc g++ ar as ld objcopy objdump ranlib strip size nm readelf; do
  ln -sf /usr/bin/riscv64-unknown-elf-$t /opt/rv32bin/riscv32-unknown-elf-$t
done
# --specs=nosys.specs is newlib-only; an empty file makes it a no-op
sudo touch /usr/lib/gcc/riscv64-unknown-elf/13.2.0/nosys.specs

cmake -S . -B build-riscv -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DPICO_PLATFORM=rp2350-riscv -DPICO_BOARD=pico2 \
  -DPICO_TOOLCHAIN_PATH=/opt/rv32bin -DPICO_CLIB=picolibc \
  -DPICOLIBC_ROOT=/usr/lib/picolibc/riscv64-unknown-elf \
  -DNO_CXX_RUNTIME=1
cmake --build build-riscv
```

`PICOLIBC_ROOT` adds picolibc's include and lib paths and passes
`-nostartfiles` (the SDK supplies its own crt0). `NO_CXX_RUNTIME` drops the
SDK's `new`/`delete` shim, which needs libstdc++ headers this toolchain does
not ship — nothing in this project is C++.

## Host simulated verification

You can test against a behavioural model of the SHA-256 peripheral and runs the whole vector
set on a PC:

```bash
cd test
g++ -O2 -std=c++17 -I stubs -I ../src -x c++ \
    ../src/miner.c ../src/sha256_sw.c sha_emul.cpp host_test.cpp -o host_test
./host_test        # 77 checks, 0 failures
```

That verifies the message layout, padding constants, second-hash construction,
target expansion, fast-reject logic and nonce plumbing. What it cannot verify
is real bus timing and ordering — which is exactly what the on-device self test
covers, and why a failing feed mode disables itself instead of mining garbage.

## Layout

```
src/main.c        self test, benchmark, re-mine demos, mining loop, console
src/miner.c/.h    RP2350 SHA-256 driver + Bitcoin target maths
src/sha256_sw.c   independent software SHA-256 (reference + baseline)
src/vectors.h     generated, every digest cross-checked against CPython hashlib
test/             host harness + peripheral model
```
