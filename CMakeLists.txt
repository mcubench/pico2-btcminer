cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico2 CACHE STRING "Board type")

# The Feitian token is an RP2350A wired to the Pico 2 reference design, but it
# carries a 2 MiB die where the pico2 board header declares 4 MiB. Addresses
# above 2 MiB alias silently onto the low 2 MiB instead of faulting, so a write
# at 0x10200000 lands on the vector table. Declare the truth.
set(PICO_FLASH_SIZE_BYTES 2097152)
set(PICO_PLATFORM rp2350 CACHE STRING "Platform")

include(pico_sdk_import.cmake)

project(pico2_btc_miner C CXX ASM)
set(CMAKE_C_STANDARD 11)

# Some riscv32 GCC builds (e.g. Ubuntu's) ship no C library. Point at a
# picolibc install to supply one. Ignored for Arm builds and unnecessary if
# your toolchain already bundles newlib.
if (DEFINED PICOLIBC_ROOT)
    add_compile_options(-isystem ${PICOLIBC_ROOT}/include)
    # -nostartfiles: the SDK ships its own crt0 (crt0_riscv.S) and its own
    # linker script, so picolibc's crt0.o must not be pulled in.
    add_link_options(-L${PICOLIBC_ROOT}/lib/rv32imac/ilp32 -L${PICOLIBC_ROOT}/lib
                     -nostartfiles)
endif()

pico_sdk_init()

# This project is pure C. Some bare-metal riscv toolchains ship no libstdc++
# headers, which breaks the SDK's new/delete shim -- nothing here uses C++,
# so drop it.
if (NO_CXX_RUNTIME)
    set_target_properties(pico_cxx_options PROPERTIES INTERFACE_SOURCES "")
endif()

add_executable(pico2_btc_miner
    src/main.c
    src/miner.c
    src/sha256_sw.c
    src/protocol.c
    src/led.c
)

target_include_directories(pico2_btc_miner PRIVATE src)

target_link_libraries(pico2_btc_miner
    pico_stdlib
    pico_multicore
    hardware_sha256
    hardware_dma
    hardware_clocks
    hardware_vreg
    hardware_adc
)

target_compile_options(pico2_btc_miner PRIVATE -O3 -Wall -Wextra -Wno-unused-parameter)

# How long to wait after reset before asserting the USB pull-up.
# -DPROTOCOL_DEFAULT=1 boots straight into btcminer-mcu protocol mode.
if (PROTOCOL_DEFAULT)
    target_compile_definitions(pico2_btc_miner PRIVATE PROTOCOL_DEFAULT=1)
    if (DEFINED PROTOCOL_CLOCK_KHZ)
        target_compile_definitions(pico2_btc_miner PRIVATE PROTOCOL_CLOCK_KHZ=${PROTOCOL_CLOCK_KHZ})
    endif()
    if (DEFINED PROTOCOL_VREG)
        target_compile_definitions(pico2_btc_miner PRIVATE PROTOCOL_VREG=${PROTOCOL_VREG})
    endif()
    # -DPROTOCOL_STOCK=1 keeps the boot clock and voltage: no overclock at all.
    if (PROTOCOL_STOCK)
        target_compile_definitions(pico2_btc_miner PRIVATE PROTOCOL_STOCK=1)
    endif()
endif()

if (DEFINED USB_SETTLE_MS)
    target_compile_definitions(pico2_btc_miner PRIVATE BOOT_USB_SETTLE_MS=${USB_SETTLE_MS})
endif()

pico_enable_stdio_usb(pico2_btc_miner 1)
pico_enable_stdio_uart(pico2_btc_miner 1)

# Run entirely from SRAM: keeps the hot loop off the XIP path and makes
# overclocking far less likely to upset flash timing.
# MANDATORY for overclocking, not an optimisation. Without it, instruction
# fetch goes through QSPI flash whose clock derives from clk_sys: at 400 MHz
# the flash is driven far beyond its rating and fetches return garbage. The
# clock-change code itself lives in flash, so an XIP build cannot survive
# raising its own clock. -DNO_COPY_TO_RAM=1 exists only for USB experiments
# at stock speed -- never overclock such a build.
if (NOT NO_COPY_TO_RAM)
    pico_set_binary_type(pico2_btc_miner copy_to_ram)
endif()

pico_add_extra_outputs(pico2_btc_miner)
