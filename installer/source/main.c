// SPDX-License-Identifier: GPL-3.0-only

#include <stdint.h>
#include "sdk_shim.h"

extern void port_outer_init_mutexes(void);
extern int  find_proc_pid_by_name(const char *name);
extern int  sys_proc_call_remote_func(int pid, void *elf_buf,
                                       uint64_t a3_unused, void *thread_name);

extern const uint8_t  embedded_inner_start[];
extern const uint8_t  embedded_inner_end[];
extern const uint64_t embedded_inner_size;

static int unlock_target_syscall_filter(int pid)
{
    intptr_t kproc = kernel_get_proc((pid_t)pid);
    if (!kproc) return -1;

    intptr_t filter_addr = 0;
    if (kernel_copyout(kproc + 0x3e8, &filter_addr, sizeof(filter_addr)) < 0)
        return -1;
    if (!filter_addr) return -1;

    unsigned long uaddr;
    uaddr = 0UL;
    if (kernel_copyin(&uaddr, filter_addr + 0xf0, sizeof(uaddr)) < 0) return -1;
    uaddr = (unsigned long)-1L;
    if (kernel_copyin(&uaddr, filter_addr + 0xf8, sizeof(uaddr)) < 0) return -1;

    return 0;
}

static int install_kernel_patch(void)
{
    intptr_t kbase = (intptr_t)KERNEL_ADDRESS_DATA_BASE;

    uint32_t s1 = kernel_get_fw_version();
    uint32_t s1_p = (s1 >> 1) & 0x55550000u;
    uint32_t s2 = kernel_get_fw_version() & 0xD5550000u;
    uint32_t v = s1_p + 2u * s2;

    klog_printf("port_outer: kpatch FW raw=0x%x derived_v=0x%x kbase=0x%lx\n",
                s1, v, (unsigned long)kbase);

    intptr_t patch_addr;
    const char *fw_label;
    switch (v) {
    case 0x3000000u: case 0x3100000u: case 0x3120000u: case 0x3200000u:
        patch_addr = kbase + 0x6466498ULL;
        fw_label = "FW 3.x";
        break;
    case 0x8010000u:
        patch_addr = kbase + 0x6505498ULL;
        fw_label = "FW 4.0";
        break;
    case 0x8000000u: case 0x8030000u: case 0x8a00000u: case 0x8a20000u:
        patch_addr = kbase + 0x6506498ULL;
        fw_label = "FW 4.x (incl. 4.51)";
        break;
    case 0xa000000u: case 0xa010000u: case 0xa200000u: case 0xaa00000u:
        patch_addr = kbase + 0x6646710ULL;
        fw_label = "FW 5.x";
        break;
    case 0x9000000u: case 0x9010000u: case 0x9a00000u:
        patch_addr = kbase + 0x6596910ULL;
        fw_label = "FW 6.x";
        break;
    case 0xb000000u: case 0xb020000u:
        patch_addr = kbase + 0xAC8088ULL;
        fw_label = "FW 7.x";
        break;
    case 0xb100000u: case 0xb800000u: case 0xb900000u: case 0xb920000u:
        patch_addr = kbase + 0xAC8088ULL;
        fw_label = "FW 7.5x";
        break;
    case 0x4000000u: case 0x4100000u: case 0x4800000u: case 0x4900000u:
        patch_addr = kbase + 0xAC3088ULL;
        fw_label = "FW 8.x";
        break;
    default:
        klog_printf("port_outer: kpatch SKIP - unsupported FW magic 0x%x\n", v);
        return -1;
    }
    klog_printf("port_outer: kpatch %s recognized; addr=0x%lx\n",
                fw_label, (unsigned long)patch_addr);

    uint8_t scratch[16];
    if (kernel_copyout(patch_addr, scratch, 16) < 0) {
        klog_puts("port_outer: kpatch READ failed\n");
        return -1;
    }
    klog_printf("port_outer: kpatch read byte[1]=0x%02x (will OR with 3)\n",
                scratch[1]);

    scratch[1] |= 3;

    if (kernel_copyin(scratch, patch_addr, 16) < 0) {
        klog_puts("port_outer: kpatch WRITE failed\n");
        return -1;
    }
    klog_printf("port_outer: kpatch WRITE OK; byte[1] now 0x%02x\n", scratch[1]);

    uint8_t verify[16];
    if (kernel_copyout(patch_addr, verify, 16) < 0) {
        klog_puts("port_outer: kpatch verify read failed\n");
        return -1;
    }
    klog_printf("port_outer: kpatch verify byte[1]=0x%02x stuck=%s\n",
                verify[1], ((verify[1] & 3) == 3) ? "YES" : "NO");
    return ((verify[1] & 3) == 3) ? 0 : -1;
}

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    port_outer_init_mutexes();

    klog_printf("port_outer: embedded inner ELF = %lu B\n",
                (unsigned long)embedded_inner_size);

    int pid = find_proc_pid_by_name("SceShellCore");
    if (pid < 0) {
        klog_puts("port_outer: SceShellCore not found in allproc walk\n");
        payload_exit(1);
        return 1;
    }
    klog_printf("port_outer: SceShellCore pid = %d\n", pid);

    if (install_kernel_patch() == 0) {
        klog_puts("port_outer: kernel patch installed\n");
    } else {
        klog_puts("port_outer: WARNING - kernel patch failed; PT_ATTACH on games will not work\n");
    }

    if (unlock_target_syscall_filter(pid) == 0) {
        klog_puts("port_outer: SceShellCore syscall_filter unlocked\n");
    } else {
        klog_puts("port_outer: WARNING - syscall_filter unlock failed\n");
    }

    long rc = sys_proc_call_remote_func(pid,
                                        (void *)embedded_inner_start,
                                        0,
                                        (void *)"libSceShareInternal.native.sprx");
    klog_printf("port_outer: sys_proc_call_remote_func rc = %ld\n", rc);

    if (rc != 0) {
        klog_puts("port_outer: inject FAILED\n");
        payload_exit(2);
        return 2;
    }

    klog_puts("port_outer: inject OK - SceShellCore now hosts inner\n");
    payload_exit(0);
    return 0;
}
