cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ese_dut)

set(ESE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
zephyr_include_directories(${ESE_ROOT}/config)

execute_process(COMMAND git -C ${ESE_ROOT} describe --always --dirty
    OUTPUT_VARIABLE ESE_GIT_REV OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
execute_process(COMMAND git -C ${ZEPHYR_WOLFSSL_MODULE_DIR} describe --always
    --dirty OUTPUT_VARIABLE ESE_WOLFSSL_GIT_REV
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)

target_sources(app PRIVATE
    src/main.c
    src/ese_platform_zephyr.c
    ${ESE_ROOT}/common/ese_algs.c
    ${ESE_ROOT}/common/ese_algbench.c
    ${ESE_ROOT}/common/ese_ctrl.c
    ${ESE_ROOT}/common/ese_dut.c
    ${ESE_ROOT}/common/ese_meas.c
    ${ESE_ROOT}/common/ese_tls.c
    ${ESE_ROOT}/common/ese_trace.c
    ${ESE_ROOT}/certs/out/ese_certs_data.c
    ${ESE_ROOT}/certs/out/ese_hbs_data.c)
target_include_directories(app PRIVATE ${ESE_ROOT}/common ${ESE_ROOT}/certs)
target_compile_definitions(app PRIVATE
    ESE_BUILD_TAG="${ESE_GIT_REV}/wolfssl-${ESE_WOLFSSL_GIT_REV}")

# The module only adds its assembly when it owns the settings, so add it here.
if(CONFIG_ARMV7_M_ARMV8_M_MAINLINE)
    set(ESE_ARM_DIR ${ZEPHYR_WOLFSSL_MODULE_DIR}/wolfcrypt/src/port/arm)
    foreach(f aes mlkem sha256 sha3 sha512)
        target_sources(app PRIVATE ${ESE_ARM_DIR}/thumb2-${f}-asm_c.c)
    endforeach()
    target_sources(app PRIVATE ${ESE_ARM_DIR}/thumb2-curve25519_c.c)
endif()
