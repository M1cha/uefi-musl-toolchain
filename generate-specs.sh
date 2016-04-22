#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cat <<EOF > $DIR/uefi-musl-gcc.specs
%rename cpp_options old_cpp_options

*cpp_options:
-ffreestanding -mword-relocations -nostdinc -isystem $DIR/lib -isystem include%s %(old_cpp_options)

*cc1:
%(cc1_cpu) -ffreestanding -mword-relocations -nostdinc -isystem $DIR/include -isystem include%s

*link_gcc_c_sequence:
--start-group %G %L --end-group

*link_libgcc:


*libgcc:
libgcc.a%s %:if-exists(libgcc_eh.a%s)

*lib:
$DIR/lib/libc.a

*startfile:
$DIR/lib/start.a

*endfile:


*link:
-nostdlib --emit-relocs --script=$DIR/misc/GccBase.lds --defsym=PECOFF_HEADER_SIZE=0x220 --entry=_ModuleEntryPoint

*esp_link:


*esp_options:


*esp_cpp_options:


EOF
