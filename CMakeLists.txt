cmake_minimum_required(VERSION 3.28)
project(firewal_linux LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXE_LINKER_FLAGS "-static")



# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake)
# Build vendored libbpf
include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install install_uapi_headers
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

ExternalProject_Add(bpftool
  PREFIX ${CMAKE_CURRENT_BINARY_DIR}/bpftool
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make bootstrap OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)
# --- Boost (static) setup ---
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME ON)

find_package(Boost REQUIRED COMPONENTS system thread)

include_directories(${Boost_INCLUDE_DIRS})

# --- OpenSSL static library setup ---
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment (like libbpf-bootstrap)
if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
  set(ARCH "x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
  set(ARCH "arm")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
  set(ARCH "arm64")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "ppc64le")
  set(ARCH "powerpc")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "mips")
  set(ARCH "mips")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "riscv64")
  set(ARCH "riscv")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "loongarch64")
  set(ARCH "loongarch")
endif()

add_subdirectory(third_party/cjson)
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool)
# set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
include_directories(${LIBBPF_INCLUDE_DIRS}/bpf)

set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)


# Create an executable for each application
file(GLOB apps ${CMAKE_CURRENT_SOURCE_DIR}/src/kernel/*.bpf.c)

set(KERNEL_HEADERS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/kernel")
set(USER_HEADERS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/user") 
set(USER_SPACE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/user/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/user/utils.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/user/connection.cpp
    # add src files here as needed
)

set(MAIN_EXECUTABLE_NAME ${CMAKE_PROJECT_NAME})
foreach(app ${apps})
  get_filename_component(app_stem ${app} NAME_WE)
  file(RELATIVE_PATH app_rel ${CMAKE_CURRENT_SOURCE_DIR} ${app})
  message(STATUS "app_stem = ${app_stem}")
  message(STATUS "app_rel  = ${app_rel}")

  set(BPF_CFLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}/src/kernel")
  bpf_object(${app_stem} ${app_rel})
  add_dependencies(${app_stem}_skel libbpf-build bpftool-build)

  # For firewal_linux, we will use the name defined by CMAKE_PROJECT_NAME
  # This part of the loop focuses on building BPF objects and their skeletons.
  # The main executable will be defined outside this loop and link to these skeletons.
endforeach()

add_executable(${MAIN_EXECUTABLE_NAME} ${USER_SPACE_SOURCES})

target_link_libraries(${MAIN_EXECUTABLE_NAME} PRIVATE
    ${LIBBPF_LIBRARIES} 
    -l:libelf.a   
    -l:libz.a     
    -l:libzstd.a  
    -lpthread     
    -lrt          
    -ldl 
    cjson 
    OpenSSL::SSL
    OpenSSL::Crypto
    Boost::system
    Boost::thread  
)

# Link the main executable to all generated eBPF skeletons
foreach(app_item ${apps})
  get_filename_component(app_stem_item ${app_item} NAME_WE)
  target_link_libraries(${MAIN_EXECUTABLE_NAME} PRIVATE ${app_stem_item}_skel)
endforeach()
# Set include directories for the main executable
target_include_directories(${MAIN_EXECUTABLE_NAME} PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR} 
    ${CMAKE_CURRENT_BINARY_DIR}/libbpf/bpf
    ${CMAKE_CURRENT_BINARY_DIR}/libbpf
    ${CMAKE_SOURCE_DIR}/third_party
)
# Add dependencies for the main executable to ensure BPF objects are built first
add_dependencies(${MAIN_EXECUTABLE_NAME} libbpf-build bpftool-build)
foreach(app_item ${apps})
    get_filename_component(app_stem_item ${app_item} NAME_WE)
    add_dependencies(${MAIN_EXECUTABLE_NAME} ${app_stem_item}_skel)
endforeach()

set(DEFAULT_POLICY_FILE_PATH "/var/lib/firewal_linux/firewall_configs.json" CACHE STRING "Default path to self defense policy JSON file")
target_compile_definitions(firewal_linux PRIVATE DEFAULT_POLICY_FILE_PATH=\"${DEFAULT_POLICY_FILE_PATH}\")
configure_file("${CMAKE_SOURCE_DIR}/configs/firewall_configs.json"
               "${CMAKE_BINARY_DIR}/firewall_configs.json"
               COPYONLY)

# --- CPack Configuration --