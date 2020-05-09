#include <linux/kernel.h>
#include <linux/string.h>
#include "include/xen.h"

typedef bool bool_t;

#define cpu_has_amd_erratum(nr) 0

#include "x86_emulate/x86_emulate.h"
#include "x86_emulate/x86_emulate.c"
