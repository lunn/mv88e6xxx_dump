/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __UTILS_H__
#define __UTILS_H__ 1

#include <sys/types.h>
#include <asm/types.h>
#include <resolv.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#ifdef HAVE_LIBBSD
#include <bsd/string.h>
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif /* __UTILS_H__ */
