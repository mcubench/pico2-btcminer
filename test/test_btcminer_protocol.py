#!/usr/bin/env python3
"""
End-to-end test: btcminer-mcu's own mining-software code driving the real
firmware protocol implementation (protocol.c) over a serial link.

Nothing is reimplemented here. The work frames are built with btcminer-mcu's
own calculate_midstate() and swap32_buffer(), sent through its own
SerialMiningDevice, and the replies checked against CPython hashlib.
"""
import asyncio, hashlib, struct, sys, os

sys.path.insert(0, "/home/claude/btcminer/mining-software")
from mining_device import SerialMiningDevice          # the real class
from sha256d_ms import calculate_midstate            # btcminer-mcu's midstate
from miner import swap32_buffer                      # btcminer-mcu's swapper

PORT = "/tmp/ttyHOST"
SHARE_TARGET = bytes.fromhex("00" * 2 + "FF" * 30)   # 0x0000FFFF..FF

fails = 0
def check(ok, what):
    global fails
    print(f"  [{'PASS' if ok else 'FAIL'}] {what}")
    if not ok: fails += 1

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def header(version, prev, merkle, t, bits, nonce):
    return (struct.pack("<L", version) + bytes.fromhex(prev)[::-1] +
            bytes.fromhex(merkle)[::-1] + struct.pack("<LLL", t, bits, nonce))

async def first_share_for(dev, hdr, limit=400):
    """
    Read shares until one is valid for `hdr`.

    Shares stream asynchronously and the device only switches work at a chunk
    boundary, so after sending new work some shares for the PREVIOUS item are
    still in flight. btcminer-mcu handles this natively: every nonce goes
    through check_nonce() against the current template and misses are logged as
    invalid. A test must model the same thing.
    """
    stale = 0
    for _ in range(limit):
        n = struct.unpack(">L", await asyncio.wait_for(dev.read(4), 30))[0]
        if sha256d(hdr[:76] + struct.pack("<L", n))[::-1] <= SHARE_TARGET:
            return n, stale
        stale += 1
    raise AssertionError("no share for this work item within limit")

def expected_shares(hdr, start, count):
    """Nonces at or after `start` whose hash meets the 16-zero-bit share target."""
    out, n = [], start
    while len(out) < count and n < 0xFFFFFFFF:
        h = sha256d(hdr[:76] + struct.pack("<L", n))[::-1]
        if h <= SHARE_TARGET: out.append(n)
        n += 1
    return out

async def main():
    dev = SerialMiningDevice(name="Pico2", port=PORT, baudrate=115200,
                             write_timeout=3, midstate=False)   # <-- the one new kwarg
    print(f"  device: {dev!r}")
    print(f"  has_midstate_support = {dev.has_midstate_support}\n")

    # ---- 1. auto-detection probe (48-byte midstate KAT, block #222222) ----
    print("1. btcminer-mcu auto-detection probe (is_mining_device)")
    ok = await dev.is_mining_device()
    check(ok, "device answers the 48-byte midstate KAT with the right nonce")

    # ---- 2. full 80-byte header, the fast path ----
    print("\n2. full-header work (has_midstate_support = False path)")
    hdr = header(0x20000000,
                 "00000000000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab",
                 "2b12fcf1bfd463ff5b6f8b1c22a710e7ae42b91e8bdb2304758dfcffc2b620e3",
                 1700000000, 0x1d00ffff, 0)
    want = expected_shares(hdr, 0, 3)
    print(f"   python says the first shares are: {[hex(n) for n in want]}")

    await dev.connect()
    await dev.write(hdr)                      # exactly what miner.py line 307 sends
    got, stale_total = [], 0
    for _ in range(len(want)):
        n, st = await first_share_for(dev, hdr)
        got.append(n); stale_total += st
    if stale_total:
        print(f"   skipped {stale_total} in-flight shares from earlier work")
    print(f"   device returned:                 {[hex(n) for n in got]}")
    check(got == want, "device finds exactly the right nonces, in order")

    for n in got:
        h = sha256d(hdr[:76] + struct.pack("<L", n))[::-1]
        check(h <= SHARE_TARGET, f"nonce {n:#010x} really meets the share target "
                                 f"({h.hex()[:12]}...)")

    # ---- 3. new work preempts old ----
    # The device keeps mining work 1 and streaming shares, so drain whatever is
    # already in flight first. btcminer-mcu itself tolerates stale shares: every
    # nonce goes through check_nonce() against the current template and misses
    # are simply logged as invalid.
    print("\n3. preemption by new work")

    hdr2 = header(0x20000000,
                  "00000000000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab",
                  "2b12fcf1bfd463ff5b6f8b1c22a710e7ae42b91e8bdb2304758dfcffc2b620e3",
                  1700000001, 0x1d00ffff, 0)   # different ntime => different work
    want2 = expected_shares(hdr2, 0, 1)
    await dev.write(hdr2)
    got2, stale = await first_share_for(dev, hdr2)
    print(f"   skipped {stale} in-flight shares from the old work item")
    print(f"   python says {want2[0]:#010x}, device returned {got2:#010x}")
    check(got2 == want2[0], "device switched, and resumed from the new start nonce")

    # ---- 4. the midstate path, built with btcminer-mcu's own helpers ----
    print("\n4. midstate work frame (built by btcminer-mcu's own code)")
    hdr3 = header(0x20000000,
                  "00000000000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab",
                  "2b12fcf1bfd463ff5b6f8b1c22a710e7ae42b91e8bdb2304758dfcffc2b620e3",
                  1700000002, 0x1d00ffff, 0)
    want3 = expected_shares(hdr3, 0, 1)
    frame = calculate_midstate(hdr3) + swap32_buffer(hdr3[64:])   # miner.py line 305
    check(len(frame) == 48, "frame is 48 bytes")
    await dev.write(frame)
    got3, stale3 = await first_share_for(dev, hdr3)
    print(f"   skipped {stale3} in-flight shares from the old work item")
    print(f"   python says {want3[0]:#010x}, device returned {got3:#010x}")
    check(got3 == want3[0], "midstate path finds the same nonce (software, slow)")

    print(f"\n=== {fails} failures ===")
    return 1 if fails else 0

sys.exit(asyncio.run(main()))
