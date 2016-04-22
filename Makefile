TOOLCHAIN_NAME ?=
EDK2_DIR ?=

$(shell mkdir -p $(PWD)/out)

MUSL_OUT := $(PWD)/out/musl
MUSL_INSTALL := $(PWD)/out/musl-install
START_OUT := $(PWD)/out/start
KERNEL_INSTALL := $(PWD)/out/kernel-headers
PACKAGE_OUT := $(PWD)/out/package

all: package

$(MUSL_OUT)/config.mak:
	mkdir -p $(MUSL_OUT)
	cd $(MUSL_OUT) && \
		../../external/musl/configure \
			--disable-shared \
			--host $(TOOLCHAIN_NAME) \
			--prefix=$(MUSL_INSTALL) \
			CC="$(TOOLCHAIN_NAME)-gcc" \
			CFLAGS="-mthumb -mword-relocations"


musl: $(MUSL_OUT)/config.mak
	$(MAKE) -C $(MUSL_OUT)
	$(MAKE) -C $(MUSL_OUT) install

start: musl
	mkdir -p $(START_OUT)
	cd $(START_OUT) && \
		cmake \
			-DCMAKE_C_COMPILER=$(TOOLCHAIN_NAME)-gcc \
			-DMUSL_INSTALL=$(MUSL_INSTALL) \
			-DEDK2_DIR=$(EDK2_DIR) \
			$(PWD)/start
	
	$(MAKE) -C $(START_OUT)

kernelheaders:
	$(MAKE) -C external/kernel-headers ARCH=arm prefix=/ DESTDIR=$(KERNEL_INSTALL) install

package: start kernelheaders
	mkdir -p $(PACKAGE_OUT)
	
	# headers
	mkdir -p $(PACKAGE_OUT)/include
	cp -R $(KERNEL_INSTALL)/include/* $(PACKAGE_OUT)/include/
	cp -R $(MUSL_INSTALL)/include/* $(PACKAGE_OUT)/include/
	
	# libs
	mkdir -p $(PACKAGE_OUT)/lib
	cp -R $(MUSL_INSTALL)/lib/*.a $(PACKAGE_OUT)/lib/
	cp $(START_OUT)/libstart.a $(PACKAGE_OUT)/lib/start.a
	
	# misc
	mkdir -p $(PACKAGE_OUT)/misc
	cp prepare.sh $(PACKAGE_OUT)/
	cp GccBase.lds $(PACKAGE_OUT)/misc/

clean:
	rm -Rf $(PWD)/out

