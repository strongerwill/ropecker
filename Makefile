obj-m += ropt.o

flags := -m32 -fno-strict-aliasing -DNDEBUG -O2 -fwrapv -Wall -Wstrict-prototypes -Isrc -Iinclude -DDISTORM_STATIC -Wimplicit-function-declaration
ropt-objs := src/decoder.o src/instructions.o src/insts.o src/mnemonics.o src/operands.o src/prefix.o src/textdefs.o src/wstring.o src/distorm.o

CFLAGS_decoder.o := $(flags)
CFLAGS_distorm.o := $(flags)
CFLAGS_instructions.o := $(flags)
CFLAGS_insts.o := $(flags)
CFLAGS_mnemonics.o := $(flags)
CFLAGS_operands.o := $(flags)
CFLAGS_prefix.o := $(flags)
CFLAGS_textdefs.o := $(flags)
CFLAGS_wstring.o := $(flags)

ropt-objs += pagefault_syscall.o branchdb.o data_struct.o monwin.o payload_checking.o x86_emulate.o emulate_memory.o emulator.o stack_check.o bi_table.o

KERNELDIR=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)
all:
	make -C $(KERNELDIR) M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
