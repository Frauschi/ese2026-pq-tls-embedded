# Builds wolfSSL from the west module with config/user_settings.h.
set(ESE_WOLFSSL_DIR ${CMAKE_CURRENT_LIST_DIR}/../modules/crypto/wolfssl)

file(GLOB ESE_WOLFSSL_SRCS
    ${ESE_WOLFSSL_DIR}/src/*.c
    ${ESE_WOLFSSL_DIR}/wolfcrypt/src/*.c)
list(FILTER ESE_WOLFSSL_SRCS EXCLUDE REGEX
    "/(sniffer|wolfcrypt_first|wolfcrypt_last|fips|fips_test|selftest)\\.c$")

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64" AND NOT ESE_NO_ASM)
    foreach(f aes mlkem sha256 sha3 sha512)
        list(APPEND ESE_WOLFSSL_SRCS
            ${ESE_WOLFSSL_DIR}/wolfcrypt/src/port/arm/armv8-${f}-asm_c.c)
    endforeach()
    list(APPEND ESE_WOLFSSL_SRCS
        ${ESE_WOLFSSL_DIR}/wolfcrypt/src/port/arm/armv8-curve25519_c.c)
endif()

function(ese_add_wolfssl name)
    add_library(${name} STATIC ${ESE_WOLFSSL_SRCS})
    target_include_directories(${name} PUBLIC
        ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../config/host
        ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../config
        ${ESE_WOLFSSL_DIR})
    target_compile_definitions(${name} PUBLIC WOLFSSL_USER_SETTINGS ${ARGN})
    if(ESE_NO_ASM)
        target_compile_definitions(${name} PUBLIC ESE_NO_ASM)
    endif()
    target_compile_definitions(${name} PRIVATE BUILDING_WOLFSSL)
    target_compile_options(${name} PRIVATE -Wno-unused -Wno-pedantic)
endfunction()
