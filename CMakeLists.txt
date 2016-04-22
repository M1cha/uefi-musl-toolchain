# project setup
cmake_minimum_required(VERSION 2.8) 
project(uefitoolchain)
set(CMAKE_BUILD_TYPE Release)

# cflags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wunused -Wshadow -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunreachable-code -Werror-implicit-function-declaration -Wwrite-strings")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -nostdlib -nostdinc -ffreestanding -fno-builtin -mword-relocations")
set(CMAKE_C_FLAGS_RELEASE "-Os")
set(CMAKE_C_FLAGS_DEBUG  "-g")

# musl endian.h
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-error=parentheses")

# printf
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPRINTF_LONG_SUPPORT")

# includes
set(INCLUDES
    ${CMAKE_SOURCE_DIR}/include

	/media/Data/repositories/git/efidroid/out/target/common/arm/uefiapp_StdlibTest/MdePkg/Include
	/media/Data/repositories/git/efidroid/out/target/common/arm/uefiapp_StdlibTest/MdePkg/Include/Arm
    /tmp/musl/include
)

# library
add_library(start STATIC
    src/entry.c
    src/syscalls.c
    src/printf.c
)
set_property(TARGET start PROPERTY INCLUDE_DIRECTORIES ${INCLUDES})
