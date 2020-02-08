cmake_minimum_required(VERSION 3.16)
project(Program)

set(CMAKE_CXX_STANDARD 20)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost REQUIRED COMPONENTS date_time)
include_directories(${Boost_INCLUDE_DIRS})

include_directories(.)
include_directories(des)
include_directories(kerberos)
include_directories(src)

add_executable(Program
        des/src/des.cpp
        des/src/des_string.cpp
        des/des.hpp
        des/des_data.hpp
        des/des_key.hpp
        des/des_string.hpp
        kerberos/src/as.cpp
        kerberos/src/kdc.cpp
        kerberos/src/tgs.cpp
        kerberos/as.hpp
        kerberos/kdc.hpp
        kerberos/packages.hpp
        kerberos/tgs.hpp
        src/client.cpp
        src/server.cpp
        .gitignore
        client.hpp
        CMakeLists.txt
        key_generator.hpp
        main.cpp
        README.md
        server.hpp)
target_link_libraries(Program ${Boost_LIBRARIES})