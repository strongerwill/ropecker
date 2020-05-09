obj-m += distorms.o 
flags := -m32 -fno-strict-aliasing -DNDEBUG -fwrapv -O2 -Wall -Wstrict-prototypes -fPIC -Isrc -Iinclude -fPIC -Wall -DDISTORM_STATIC
distorms-objs := decoder.o instructions.o insts.o mnemonics.o operands.o prefix.o textdefs.o wstring.o distorm.o

CFLAGS_decoder.o := $(flags)
CFLAGS_distorm.o := $(flags)
CFLAGS_instructions.o := $(flags)
CFLAGS_insts.o := $(flags)
CFLAGS_mnemonics.o := $(flags)
CFLAGS_operands.o := $(flags)
CFLAGS_prefix.o := $(flags)
CFLAGS_textdefs.o := $(flags)
CFLAGS_wstring.o := $(flags)
