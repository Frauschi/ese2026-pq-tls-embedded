cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ese_footprint)

set(ESE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
zephyr_include_directories(${ESE_ROOT}/config)

set(FP_ITEM "baseline" CACHE STRING "What main.c links in, see src/main.c")
string(TOUPPER "${FP_ITEM}" fp)
target_sources(app PRIVATE src/main.c)
target_compile_definitions(app PRIVATE FP_${fp})

if(CONFIG_ARMV7_M_ARMV8_M_MAINLINE)
    set(ESE_ARM_DIR ${ZEPHYR_WOLFSSL_MODULE_DIR}/wolfcrypt/src/port/arm)
    foreach(f aes mlkem sha256 sha3 sha512)
        target_sources(app PRIVATE ${ESE_ARM_DIR}/thumb2-${f}-asm_c.c)
    endforeach()
    target_sources(app PRIVATE ${ESE_ARM_DIR}/thumb2-curve25519_c.c)
endif()
