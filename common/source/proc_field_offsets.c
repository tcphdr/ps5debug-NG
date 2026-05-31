// SPDX-License-Identifier: GPL-3.0-only

#include <ps5/kernel.h>
#include "proc_field_offsets.h"

int proc_get_field_offsets(struct proc_field_offsets *out)
{
    static int cached = 0;
    static struct proc_field_offsets c;

    if (!cached) {
        switch (kernel_get_fw_version() & 0xffff0000u) {
        case 0x6000000u: case 0x6020000u: case 0x6500000u:                    /* 6.x  */
            c.name = 0x5C4; c.path = 0x5E4; c.titleid = 0x498; c.contentid = 0x4EC;
            c.known = 1;
            break;

        case 0x7000000u: case 0x7010000u:                                     /* 7.0x */
        case 0x8000000u: case 0x8200000u: case 0x8400000u: case 0x8600000u:   /* 8.x  */
            c.name = 0x5D4; c.path = 0x5F4; c.titleid = 0x49A; c.contentid = 0x4FC;
            c.known = 1;
            break;

        case 0x3000000u: case 0x3100000u: case 0x3200000u: case 0x3210000u:   /* 3.x  */
        case 0x4020000u:                                                      /* 4.02 */
        case 0x4000000u: case 0x4030000u: case 0x4500000u: case 0x4510000u:   /* 4.x  */
        case 0x5000000u: case 0x5020000u: case 0x5100000u: case 0x5500000u:   /* 5.x  */
        case 0x7200000u: case 0x7400000u: case 0x7600000u: case 0x7610000u:   /* 7.5x */
            c.name = 0x59C; c.path = 0x5BC; c.titleid = 0x470; c.contentid = 0x4C4;
            c.known = 1;
            break;

        default:
            c.name = 0; c.path = 0; c.titleid = 0; c.contentid = 0;
            c.known = 0;
            break;
        }
        cached = 1;
    }

    *out = c;
    return c.known ? 0 : -1;
}
