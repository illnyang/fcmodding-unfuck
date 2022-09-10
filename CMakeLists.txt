cmake_minimum_required(VERSION 3.23)
project(fc3_noarman)

set(CMAKE_CXX_STANDARD 23)

# https://github.com/cpm-cmake/CPM.cmake/releases/latest/download/get_cpm.cmake
set(CPM_DOWNLOAD_VERSION 0.35.1)

if(CPM_SOURCE_CACHE)
    get_filename_component(CPM_SOURCE_CACHE ${CPM_SOURCE_CACHE} ABSOLUTE)
    set(CPM_DOWNLOAD_LOCATION "${CPM_SOURCE_CACHE}/cpm/CPM_${CPM_DOWNLOAD_VERSION}.cmake")
elseif(DEFINED ENV{CPM_SOURCE_CACHE})
    set(CPM_DOWNLOAD_LOCATION "$ENV{CPM_SOURCE_CACHE}/cpm/CPM_${CPM_DOWNLOAD_VERSION}.cmake")
else()
    set(CPM_DOWNLOAD_LOCATION "${CMAKE_BINARY_DIR}/cmake/CPM_${CPM_DOWNLOAD_VERSION}.cmake")
endif()

if(NOT (EXISTS ${CPM_DOWNLOAD_LOCATION}))
    message(STATUS "Downloading CPM.cmake to ${CPM_DOWNLOAD_LOCATION}")
    file(DOWNLOAD
            https://github.com/cpm-cmake/CPM.cmake/releases/download/v${CPM_DOWNLOAD_VERSION}/CPM.cmake
            ${CPM_DOWNLOAD_LOCATION}
    )
endif()

include(${CPM_DOWNLOAD_LOCATION})

CPMAddPackage(
        NAME VC-LTL
        URL https://github.com/Chuyu-Team/VC-LTL5/releases/download/v5.0.5/VC-LTL-5.0.5-Binary.7z
        VERSION 5.0.5
        DOWNLOAD_ONLY True
)

if(VC-LTL_ADDED)
    set(VC-LTL_SDK_VER 6.0.6000.0)
    set(VC-LTL_TARGET_ARCH x64)

    add_library(VC-LTL INTERFACE)

    target_link_libraries(VC-LTL INTERFACE
            # MultiThreaded
            ${VC-LTL_SOURCE_DIR}/TargetPlatform/${VC-LTL_SDK_VER}/lib/${VC-LTL_TARGET_ARCH}/libvcruntime.lib
            ${VC-LTL_SOURCE_DIR}/TargetPlatform/${VC-LTL_SDK_VER}/lib/${VC-LTL_TARGET_ARCH}/libucrt.lib

            # MultiThreadedDLL
            #${VC-LTL_SOURCE_DIR}/TargetPlatform/${VC-LTL_SDK_VER}/lib/${VC-LTL_TARGET_ARCH}/vcruntime.lib
            #${VC-LTL_SOURCE_DIR}/TargetPlatform/${VC-LTL_SDK_VER}/lib/${VC-LTL_TARGET_ARCH}/ucrt.lib
    )

    target_include_directories(VC-LTL INTERFACE
            ${VC-LTL_SOURCE_DIR}/TargetPlatform/${VC-LTL_SDK_VER}/header
   )
endif()

CPMAddPackage(
        NAME phnt
        URL https://github.com/processhacker/phnt/archive/refs/heads/master.zip
        DOWNLOAD_ONLY True
)
if(phnt_ADDED)
    add_library(phnt INTERFACE)
    target_include_directories(phnt INTERFACE ${phnt_SOURCE_DIR})
endif()

CPMAddPackage("gh:TsudaKageyu/minhook#master")
CPMAddPackage("gh:serge-sans-paille/frozen#master")

add_library(fc3_noarman SHARED src/DLLMain.cpp)

set_target_properties(fc3_noarman PROPERTIES
        OUTPUT_NAME "version"
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

target_compile_options(fc3_noarman PRIVATE
        -fmacro-prefix-map=${PROJECT_SOURCE_DIR}=.
        -fdebug-prefix-map=${PROJECT_SOURCE_DIR}=.
        -fcoverage-prefix-map=${PROJECT_SOURCE_DIR}=.
        -ffile-prefix-map=${PROJECT_SOURCE_DIR}=.
        -fdebug-compilation-dir=.
        -ffile-compilation-dir=.

        -no-canonical-prefixes
        -fbuild-session-timestamp=0
        -ffile-reproducible

        -Wno-builtin-macro-redefined
        -D__DATE__="Apr 2 2006"
        -D__TIME__="21:37:01"
        -D__TIMESTAMP__=0

        -DJM_XORSTR_DISABLE_AVX_INTRINSICS=1

        -Wno-microsoft-cast
)

target_link_options(fc3_noarman PRIVATE
        LINKER:-PDBSourcePath:,
        LINKER:-PDBAltPath:"--- SINCERE FUCK YOU TO ALL UBISOFT BOOTLICKERS ---",
        LINKER:-timestamp:0,
        LINKER:-DEF:${CMAKE_CURRENT_LIST_DIR}/src/version_proxy.def
)

target_link_libraries(fc3_noarman PRIVATE VC-LTL phnt minhook frozen)