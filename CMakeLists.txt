# Host-side build: cert generator, host helper and the Linux DUT.
cmake_minimum_required(VERSION 3.20)
project(ese_2026 C)

set(CMAKE_C_STANDARD 11)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(ESE_DUT_ONLY "Build only the Linux DUT (cross/Pi builds)" OFF)
option(ESE_STATIC "Link executables statically" OFF)
set(ESE_PLATFORM_NAME "" CACHE STRING "Platform name the Linux DUT reports")
option(ESE_NO_ASM "Portable C only (fallback if the Arm assembly will not build)" OFF)
option(ESE_HEAP_TRACE "Heap-event trace in the Linux DUT (slows it down)" OFF)
set(ESE_PQC_PROFILE "" CACHE STRING
    "PQC profile of the Linux DUT: smallmem, smallmem-fast, cache or small")
set(ESE_FALCON_FPR "int" CACHE STRING "Falcon fpr backend of the Linux DUT: int, double or neon")

include(cmake/wolfssl.cmake)

if(ESE_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

find_package(Threads REQUIRED)

execute_process(COMMAND git -C ${CMAKE_SOURCE_DIR} describe --always --dirty
    OUTPUT_VARIABLE ESE_GIT_REV OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
execute_process(COMMAND git -C ${ESE_WOLFSSL_DIR} describe --always --dirty
    OUTPUT_VARIABLE ESE_WOLFSSL_GIT_REV OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)

set(ESE_COMMON_SRCS
    common/ese_algs.c
    common/ese_algbench.c
    common/ese_ctrl.c
    common/ese_meas.c
    common/ese_tls.c
    common/ese_trace.c
    common/posix/ese_platform_posix.c
    certs/out/ese_certs_data.c
    certs/out/ese_hbs_data.c)
set(ESE_COMMON_INCS common certs)

set(ESE_DUT_DEFS)
if(ESE_HEAP_TRACE)
    list(APPEND ESE_DUT_DEFS ESE_HEAP_TRACE)
endif()
if(ESE_PQC_PROFILE AND NOT ESE_PQC_PROFILE STREQUAL "default")
    string(TOUPPER "${ESE_PQC_PROFILE}" p)
    string(REPLACE "-" "_" p "${p}")
    list(APPEND ESE_DUT_DEFS ESE_PQC_${p})
endif()
if(ESE_FALCON_FPR STREQUAL "double")
    list(APPEND ESE_DUT_DEFS WOLFSSL_FALCON_FPR_DOUBLE)
elseif(ESE_FALCON_FPR STREQUAL "neon")
    list(APPEND ESE_DUT_DEFS WOLFSSL_FALCON_FPR_DOUBLE WOLFSSL_FALCON_FFT_NEON)
elseif(NOT ESE_FALCON_FPR STREQUAL "int")
    message(FATAL_ERROR "ESE_FALCON_FPR must be int, double or neon")
endif()
ese_add_wolfssl(wolfssl_dut ${ESE_DUT_DEFS})
add_executable(ese_dut dut/linux/main.c common/ese_dut.c ${ESE_COMMON_SRCS})
target_include_directories(ese_dut PRIVATE ${ESE_COMMON_INCS})
target_compile_definitions(ese_dut PRIVATE
    ESE_BUILD_TAG="${ESE_GIT_REV}/wolfssl-${ESE_WOLFSSL_GIT_REV}")
target_link_libraries(ese_dut wolfssl_dut m Threads::Threads)
if(ESE_PLATFORM_NAME)
    target_compile_definitions(ese_dut PRIVATE
        ESE_PLATFORM_NAME="${ESE_PLATFORM_NAME}")
endif()
if(NOT APPLE)
    target_link_options(ese_dut PRIVATE -Wl,-z,now)
endif()

if(NOT ESE_DUT_ONLY)
    ese_add_wolfssl(wolfssl_host ESE_HOST_TOOLS WOLFSSL_FALCON_FPR_DOUBLE)
    # The peer's crypto time lands in DUT-client TTFB, so use every host CPU feature.
    if(NOT ESE_NO_ASM AND NOT APPLE)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
            target_compile_options(wolfssl_host PUBLIC -march=armv8-a+crypto)
            target_compile_definitions(wolfssl_host PUBLIC WOLFSSL_FALCON_FFT_NEON)
        else()
            target_compile_options(wolfssl_host PUBLIC -march=native)
        endif()
    endif()

    add_executable(ese_certgen certs/gen/certgen.c common/ese_algs.c)
    target_include_directories(ese_certgen PRIVATE common certs)
    target_link_libraries(ese_certgen wolfssl_host m)

    add_executable(ese_hbsgen certs/gen/hbsgen.c common/ese_algs.c)
    target_include_directories(ese_hbsgen PRIVATE common certs)
    target_link_libraries(ese_hbsgen wolfssl_host m)

    add_executable(ese_host host/ese_host.c ${ESE_COMMON_SRCS})
    target_include_directories(ese_host PRIVATE ${ESE_COMMON_INCS})
    target_compile_definitions(ese_host PRIVATE
        ESE_GIT_REV="${ESE_GIT_REV}" ESE_WOLFSSL_GIT_REV="${ESE_WOLFSSL_GIT_REV}")
    target_link_libraries(ese_host wolfssl_host m Threads::Threads)

    add_executable(ese_wctest ${ESE_WOLFSSL_DIR}/wolfcrypt/test/test.c)
    target_link_libraries(ese_wctest wolfssl_host m Threads::Threads)
endif()
