#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cat <<EOF > $DIR/uefi-musl-gcc.specs
%rename cpp_options old_cpp_options

*cpp_options:
-ffreestanding -mword-relocations -nostdinc -isystem $DIR/lib -isystem include%s %(old_cpp_options)

*cc1:
%(cc1_cpu) -ffreestanding -mword-relocations -nostdinc -isystem $DIR/include -isystem include%s

*link_libgcc:
-L$DIR/lib -L .%s

*libgcc:
libgcc.a%s %:if-exists(libgcc_eh.a%s)

*startfile:
$DIR/lib/start.a

*endfile:


*link:
-nostdlib --emit-relocs %{shared:-shared} %{static:-static} --script=$DIR/misc/GccBase.lds --defsym=PECOFF_HEADER_SIZE=0x220 --entry=_ModuleEntryPoint

*esp_link:


*esp_options:


*esp_cpp_options:


EOF

mkdir -p $DIR/bin
cat <<EOF > $DIR/bin/arm-uefi-gcc
#!/bin/sh
exec "\${REALGCC:-arm-linux-gnueabi-gcc}" "\$@" -specs "$DIR/uefi-musl-gcc.specs"
EOF
chmod +x $DIR/bin/arm-uefi-gcc

genforward() {
cat <<EOF > $DIR/bin/arm-uefi-$1
#!/bin/sh
exec "\${REALGCC:-arm-linux-gnueabi-$1}" "\$@"
EOF
chmod +x $DIR/bin/arm-uefi-$1
}

genforward ar
genforward strip


