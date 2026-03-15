cmake_minimum_required(VERSION 3.10)
project(SovereignSyncPII C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3")

# Add shared library
add_library(pii_filter SHARED
    pii_filter.c
)

# Include directories
target_include_directories(pii_filter PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Platform-specific linking
if(WIN32)
    # Windows: Try to find regex library
    find_library(REGEX_LIBRARY regex)
    if(REGEX_LIBRARY)
        target_link_libraries(pii_filter ${REGEX_LIBRARY})
    endif()
    set_target_properties(pii_filter PROPERTIES
        OUTPUT_NAME "libpii_filter"
        SUFFIX ".dll"
    )
else()
    # Unix-like systems (Linux, macOS)
    # Try PCRE2 first, fallback to regex
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(PCRE2 QUIET libpcre2-8)
        if(PCRE2_FOUND)
            target_include_directories(pii_filter PRIVATE ${PCRE2_INCLUDE_DIRS})
            target_link_libraries(pii_filter ${PCRE2_LIBRARIES})
        else()
            # Fallback to system regex
            target_link_libraries(pii_filter regex)
        endif()
    else()
        target_link_libraries(pii_filter regex)
    endif()

    set_target_properties(pii_filter PROPERTIES
        OUTPUT_NAME "pii_filter"
        SUFFIX ".so"
    )
endif()

# Installation
install(TARGETS pii_filter
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
