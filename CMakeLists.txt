cmake_minimum_required(VERSION 3.20)
project(asio_web_framework VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Define DEV flag option
option(DEV "Enable development build with strict flags and sanitizers" ON)

# Find required packages
find_package(Threads REQUIRED)

# Try to find ASIO
find_path(ASIO_INCLUDE_DIR
    NAMES asio.hpp
    PATHS 
        /usr/include
        /usr/local/include
        /opt/homebrew/include
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/asio/include
    PATH_SUFFIXES asio
)

# Try to find nlohmann/json
find_path(NLOHMANN_JSON_INCLUDE_DIR
    NAMES nlohmann/json.hpp
    PATHS
        /usr/include
        /usr/local/include
        /opt/homebrew/include
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann_json/include
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/json/include
)

# If not found, try using FetchContent to download them
if(NOT ASIO_INCLUDE_DIR OR NOT NLOHMANN_JSON_INCLUDE_DIR)
    include(FetchContent)
    
    # Fetch ASIO if not found
    if(NOT ASIO_INCLUDE_DIR)
        message(STATUS "ASIO not found locally, fetching from GitHub...")
        FetchContent_Declare(
            asio
            GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
            GIT_TAG asio-1-30-2
            GIT_SHALLOW TRUE
        )
        FetchContent_MakeAvailable(asio)
        set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/asio/include)
    endif()
    
    # Fetch nlohmann/json if not found
    if(NOT NLOHMANN_JSON_INCLUDE_DIR)
        message(STATUS "nlohmann/json not found locally, fetching from GitHub...")
        FetchContent_Declare(
            nlohmann_json
            GIT_REPOSITORY https://github.com/nlohmann/json.git
            GIT_TAG v3.11.3
            GIT_SHALLOW TRUE
        )
        FetchContent_MakeAvailable(nlohmann_json)
        set(NLOHMANN_JSON_INCLUDE_DIR ${nlohmann_json_SOURCE_DIR}/include)
    endif()
endif()

# Verify we found the headers
if(NOT ASIO_INCLUDE_DIR)
    message(FATAL_ERROR "ASIO headers not found!")
endif()

if(NOT NLOHMANN_JSON_INCLUDE_DIR)
    message(FATAL_ERROR "nlohmann/json headers not found!")
endif()

message(STATUS "Found ASIO headers at: ${ASIO_INCLUDE_DIR}")
message(STATUS "Found nlohmann/json headers at: ${NLOHMANN_JSON_INCLUDE_DIR}")

# Create the executable
add_executable(${PROJECT_NAME} web_framework.cpp)

# Set include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${ASIO_INCLUDE_DIR}
    ${NLOHMANN_JSON_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE 
    Threads::Threads
)

# Platform-specific settings
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32 wsock32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE 
        _WIN32_WINNT=0x0601
        ASIO_STANDALONE
        ASIO_NO_DEPRECATED
    )
else()
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        ASIO_STANDALONE
        ASIO_NO_DEPRECATED
    )
endif()

# Development build settings
if(DEV)
    message(STATUS "Development build enabled - adding strict compiler flags and sanitizers")
    
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${PROJECT_NAME} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -fsanitize=address
            -fno-omit-frame-pointer
        )
        
        target_link_options(${PROJECT_NAME} PRIVATE
            -fsanitize=address
        )
        
        # Additional useful warnings for development
        if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            target_compile_options(${PROJECT_NAME} PRIVATE
                -Wthread-safety
                -Wthread-safety-beta
            )
        endif()
    elseif(MSVC)
        target_compile_options(${PROJECT_NAME} PRIVATE
            /W4
            /permissive-
        )
    endif()
    
    # Set debug build type if not specified
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Debug)
    endif()
else()
    # Release build optimizations
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release)
    endif()
    
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${PROJECT_NAME} PRIVATE
            -O3
            -DNDEBUG
        )
    elseif(MSVC)
        target_compile_options(${PROJECT_NAME} PRIVATE
            /O2
            /DNDEBUG
        )
    endif()
endif()

# Print build configuration
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Development build: ${DEV}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")

# Installation rules (optional)
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)

# Create a static files directory in build output
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/static)

# Copy any static files if they exist
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/static)
    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/static/
         DESTINATION ${CMAKE_BINARY_DIR}/static/)
endif()

# If there's an sse.html file in the source directory, copy it
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/sse.html)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/sse.html
                   ${CMAKE_BINARY_DIR}/sse.html COPYONLY)
endif()

# Print usage instructions
message(STATUS "")
message(STATUS "Usage:")
message(STATUS "  mkdir build && cd build")
message(STATUS "  cmake .. -DDEV=ON              # For development build")
message(STATUS "  cmake .. -DDEV=OFF             # For release build (default)")
message(STATUS "  cmake --build .")
message(STATUS "")
message(STATUS "The executable will be: ${CMAKE_BINARY_DIR}/${PROJECT_NAME}")
message(STATUS "")