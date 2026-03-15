cmake_minimum_required(VERSION 3.10)
project(sovereign-sync C)

# C Standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -march=native")

# PCRE2 
find_package(PCRE2 REQUIRED)

# Add source files
set(SOURCES
    src/pii_scanner.c
)

# Create shared library
add_library(pii_scanner SHARED ${SOURCES})

# Link PCRE2
target_include_directories(pii_scanner PRIVATE include)
target_link_libraries(pii_scanner PRIVATE PCRE2::PCRE2)

# Set output directory
set_target_properties(pii_scanner PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

# Optional: Build tests
enable_testing()

# PII Scanner test executable
add_executable(pii_scanner_test tests/test_pii_scanner.c src/pii_scanner.c)
target_include_directories(pii_scanner_test PRIVATE include)
target_link_libraries(pii_scanner_test PRIVATE PCRE2::PCRE2)

add_test(NAME PIIScannerTests COMMAND pii_scanner_test)
