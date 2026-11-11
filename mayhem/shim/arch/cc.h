#ifndef MAYHEM_ARCH_CC_H
#define MAYHEM_ARCH_CC_H

#include <endian.h>
#include <stdio.h>
#include <stdlib.h>

#define BYTE_ORDER __BYTE_ORDER
#define LWIP_PLATFORM_DIAG(x)   do { } while (0)
#define LWIP_PLATFORM_ASSERT(x) abort()

#endif
