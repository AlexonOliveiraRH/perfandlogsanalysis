## RHEL - Kdump and sosreport analysis, and performance troubleshooting

This is a very (very!) basic guide on how to enable and configure kdump and sos to collect and analyze vmcore and sosreport log files. Also, an overview on how to make a very simple performance troubleshooting.

---

### Recommended Training:

1. [**RH342 - Red Hat Enterprise Linux Diagnostics and Troubleshooting**](https://www.redhat.com/en/services/training/rh342-red-hat-enterprise-linux-diagnostics-and-troubleshooting)
2. [**RH442 - Red Hat Performance Tuning: Linux in Physical, Virtual, and Cloud**](https://www.redhat.com/en/services/training/rh442-red-hat-enterprise-performance-tuning)

---

### Support/Reference Documents

 1. **[Monitoring and managing system status and performance](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html-single/monitoring_and_managing_system_status_and_performance/index#doc-wrapper)**
 2. **[Chapter 10. Installing kdump](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html-single/managing_monitoring_and_updating_the_kernel/index#installing-kdump_managing-monitoring-and-updating-the-kernel)**
3. **[How to use the SysRq facility to collect information from a RHEL server](https://access.redhat.com/solutions/2023)**
4. **[Vmcore analysis techniques](https://access.redhat.com/articles/1406253)**
5. **[Kernel Oops Analyzer](https://access.redhat.com/labs/kerneloopsanalyzer/)**
6. **[Kdump Helper](https://access.redhat.com/labs/kdumphelper/wizard/)**
7. **[A Guide to Unexpected System Restarts](https://access.redhat.com/articles/206873)**
8. **[How to analyze and interpret sar data](https://access.redhat.com/articles/325783)**
9. **[xsos -- a tool for sysadmins and support techs](https://access.redhat.com/discussions/469323)**
10. **[Brendan Gregg - Linux Performance](https://www.brendangregg.com/linuxperf.html)**

---

## Logs (sosreport and kdump) - Examples:

### Check if kdump is enabled

    [root@demo ~]# rpm -q kexec-tools
    kexec-tools-2.0.20-68.el8.x86_64
    
    [root@demo ~]# systemctl status kdump.service 
    ● kdump.service - Crash recovery kernel arming
       Loaded: loaded (/usr/lib/systemd/system/kdump.service; enabled; vendor preset: enabled)
       Active: active (exited) since Wed 2022-08-17 17:30:31 -03; 1 day 20h ago
     Main PID: 1326 (code=exited, status=0/SUCCESS)
        Tasks: 0 (limit: 23644)
       Memory: 0B
       CGroup: /system.slice/kdump.service
    
    ago 17 17:30:29 demo.example.local systemd[1]: Starting Crash recovery kernel arming...
    ago 17 17:30:31 demo.example.local kdumpctl[1338]: kdump: kexec: loaded kdump kernel
    ago 17 17:30:31 demo.example.local kdumpctl[1338]: kdump: Starting kdump: [OK]
    ago 17 17:30:31 demo.example.local systemd[1]: Started Crash recovery kernel arming.
    
    [root@demo ~]# grep crash /etc/default/grub 
    GRUB_CMDLINE_LINUX="crashkernel=auto resume=/dev/mapper/VG_01-swap rd.lvm.lv=VG_01/root rd.lvm.lv=VG_01/swap rhgb quiet"

### Enable kdump

    [root@demo ~]# kdumpctl estimate
    Reserved crashkernel:    192M
    Recommended crashkernel: 192M
    
    Kernel image size:   54M
    Kernel modules size: 8M
    Initramfs size:      26M
    Runtime reservation: 64M
    Large modules:
        xfs: 1556480
    
    [root@demo ~]# kdumpctl showmem
    kdump: Reserved 192MB memory for crash kernel

#### RHEL 8 (Manually open and edit the grub config file in the kernel line with the crashkernel parameter)

    [root@demo ~]# vi /etc/default/grub
    
    [root@demo ~]# grep crash /etc/default/grub 
    GRUB_CMDLINE_LINUX="crashkernel=192M resume=/dev/mapper/VG_01-swap rd.lvm.lv=VG_01/root rd.lvm.lv=VG_01/swap rhgb quiet"
    
    [root@demo ~]# grub2-mkconfig -o /boot/grub2/grub.cfg
    
    [root@demo ~]# reboot

#### RHEL 9 (Use the kdumpctl tool)

    [root@demo ~]# kdumpctl reset-crashkernel --kernel=ALL
    
    [root@demo ~]# grubby --update-kernel ALL --args "crashkernel=192M”
    
    [root@demo ~]# grep crash /etc/default/grub 
    GRUB_CMDLINE_LINUX="crashkernel=192M resume=/dev/mapper/VG_01-swap rd.lvm.lv=VG_01/root rd.lvm.lv=VG_01/swap rhgb quiet"
    
    [root@demo ~]# reboot

### Testing vmcore creation (PS. The system will crash intentionally and will reboot)

    [root@demo ~]# echo c > /proc/sysrq-trigger
    
    [root@demo ~]# ls /var/crash/127.0.0.1-2022-08-16-16\:32\:51/
    kexec-dmesg.log  vmcore  vmcore-dmesg.txt
    
### Check reboot triggered by the user

    [root@demo ~]# grep 'Command line' /var/log/messages
    Aug 17 15:01:47 demo kernel: Command line: BOOT_IMAGE=(hd0,msdos1)/vmlinuz-4.18.0-372.16.1.el8_6.x86_64 root=/dev/mapper/VG_01-root ro crashkernel=auto resume=/dev/mapper/VG_01-swap rd.lvm.lv=VG_01/root rd.lvm.lv=VG_01/swap rhgb quiet
    Aug 17 15:32:14 demo kernel: Command line: BOOT_IMAGE=(hd0,msdos1)/vmlinuz-4.18.0-348.20.1.el8_5.x86_64 root=/dev/mapper/VG_01-root ro crashkernel=auto resume=/dev/mapper/VG_01-swap rd.lvm.lv=VG_01/root rd.lvm.lv=VG_01/swap rhgb quiet
    Aug 17 15:49:50 demo kernel: Command line: BOOT_IMAGE=(hd0,msdos1)/vmlinuz-4.18.0-372.16.1.el8_6.x86_64 root=/dev/mapper/VG_01-root ro crashkernel=auto resume=/dev/mapper/VG_01-swap rd.lvm.lv=VG_01/root rd.lvm.lv=VG_01/swap rhgb quiet
    Aug 17 16:36:30 demo kernel: Command line: BOOT_IMAGE=(hd0,msdos1)/vmlinuz-4.18.0-372.19.1.el8_6.x86_64 root=/dev/mapper/VG_01-root ro crashkernel=auto resume=/dev/mapper/VG_01-swap rd.lvm.lv=VG_01/root rd.lvm.lv=VG_01/swap rhgb quiet
    Aug 17 17:23:39 demo kernel: Command line: BOOT_IMAGE=(hd0,msdos1)/vmlinuz-4.18.0-372.19.1.el8_6.x86_64 root=/dev/mapper/VG_01-root ro crashkernel=auto resume=/dev/mapper/VG_01-swap rd.lvm.lv=VG_01/root rd.lvm.lv=VG_01/swap rhgb quiet
    Aug 17 17:30:22 demo kernel: Command line: BOOT_IMAGE=(hd0,msdos1)/vmlinuz-4.18.0-372.19.1.el8_6.x86_64 root=/dev/mapper/VG_01-root ro crashkernel=auto resume=/dev/mapper/VG_01-swap rd.lvm.lv=VG_01/root rd.lvm.lv=VG_01/swap rhgb quiet
   
    [root@demo ~]# last | grep reboot
    reboot   system boot  4.18.0-372.19.1. Wed Aug 17 17:30   still running
    reboot   system boot  4.18.0-372.19.1. Wed Aug 17 17:23 - 17:30  (00:06)
    reboot   system boot  4.18.0-372.19.1. Wed Aug 17 16:36 - 17:23  (00:46)
    reboot   system boot  4.18.0-372.16.1. Wed Aug 17 15:49 - 16:36  (00:46)
    reboot   system boot  4.18.0-348.20.1. Wed Aug 17 15:32 - 15:49  (00:17)
    reboot   system boot  4.18.0-372.16.1. Wed Aug 17 15:01 - 15:31  (00:30)

### Basic vmcore analysis (PS. If it's in another system, make sure you have the same kernel version of the generated vmcore)

    [root@demo ~]# dnf repolist
    Updating Subscription Management repositories.
    repo id                                                        repo name
    advanced-virt-for-rhel-8-x86_64-rpms                           Advanced Virtualization for RHEL 8 x86_64 (RPMs)
    codeready-builder-for-rhel-8-x86_64-rpms                       Red Hat CodeReady Linux Builder for RHEL 8 x86_64 (RPMs)
    epel                                                           Extra Packages for Enterprise Linux 8 - x86_64
    epel-modular                                                   Extra Packages for Enterprise Linux Modular 8 - x86_64
    rhel-8-for-x86_64-appstream-debug-rpms                         Red Hat Enterprise Linux 8 for x86_64 - AppStream (Debug RPMs)
    rhel-8-for-x86_64-appstream-rpms                               Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
    rhel-8-for-x86_64-baseos-debug-rpms                            Red Hat Enterprise Linux 8 for x86_64 - BaseOS (Debug RPMs)
    rhel-8-for-x86_64-baseos-rpms                                  Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
    rhel-8-for-x86_64-highavailability-rpms                        Red Hat Enterprise Linux 8 for x86_64 - High Availability (RPMs)
    rhel-8-for-x86_64-resilientstorage-rpms                        Red Hat Enterprise Linux 8 for x86_64 - Resilient Storage (RPMs)
    rhel-8-for-x86_64-rt-rpms                                      Red Hat Enterprise Linux 8 for x86_64 - Real Time (RPMs)
    rhel-8-for-x86_64-supplementary-debug-rpms                     Red Hat Enterprise Linux 8 for x86_64 - Supplementary (Debug RPMs)
    rhel-8-for-x86_64-supplementary-rpms                           Red Hat Enterprise Linux 8 for x86_64 - Supplementary (RPMs)
    rsawaroha                                                      rsaw aroha rpms for Fedora/RHEL6+
    satellite-client-6-for-rhel-8-x86_64-rpms                      Red Hat Satellite Client 6 for RHEL 8 x86_64 (RPMs)
    
    [root@demo ~]# rpm -qa | grep kernel
    kernel-modules-extra-4.18.0-372.19.1.el8_6.x86_64
    kernel-modules-4.18.0-372.16.1.el8_6.x86_64
    kernel-devel-4.18.0-372.16.1.el8_6.x86_64
    kernel-debug-modules-4.18.0-372.16.1.el8_6.x86_64
    kernel-tools-4.18.0-372.19.1.el8_6.x86_64
    kernel-core-4.18.0-372.19.1.el8_6.x86_64
    kernel-debuginfo-common-x86_64-4.18.0-372.19.1.el8_6.x86_64
    kernel-debug-modules-extra-4.18.0-372.19.1.el8_6.x86_64
    kernel-debuginfo-4.18.0-372.16.1.el8_6.x86_64
    kernel-debug-modules-4.18.0-372.19.1.el8_6.x86_64
    kernel-debuginfo-4.18.0-372.19.1.el8_6.x86_64
    kernel-4.18.0-372.19.1.el8_6.x86_64
    kernel-devel-4.18.0-372.19.1.el8_6.x86_64
    kernel-headers-4.18.0-372.19.1.el8_6.x86_64
    kernel-debuginfo-common-x86_64-4.18.0-372.16.1.el8_6.x86_64
    kernel-4.18.0-372.16.1.el8_6.x86_64
    kernel-modules-extra-4.18.0-372.16.1.el8_6.x86_64
    kernel-debug-modules-extra-4.18.0-372.16.1.el8_6.x86_64
    kernel-modules-4.18.0-372.19.1.el8_6.x86_64
    kernel-core-4.18.0-372.16.1.el8_6.x86_64
    kernel-debug-core-4.18.0-372.19.1.el8_6.x86_64
    kernel-debug-core-4.18.0-372.16.1.el8_6.x86_64
    kernel-tools-libs-4.18.0-372.19.1.el8_6.x86_64
    
    [root@demo ~]# rpm -qa | grep crash
    crash-7.3.1-5.el8.x86_64
    
    [root@demo ~]# crash /usr/lib/debug/lib/modules/4.18.0-372.16.1.el8_6.x86_64/vmlinux /var/crash/127.0.0.1-2022-08-16-16\:32\:51/vmcore
    
    crash 7.3.1-5.el8
    Copyright (C) 2002-2021  Red Hat, Inc.
    Copyright (C) 2004, 2005, 2006, 2010  IBM Corporation
    Copyright (C) 1999-2006  Hewlett-Packard Co
    Copyright (C) 2005, 2006, 2011, 2012  Fujitsu Limited
    Copyright (C) 2006, 2007  VA Linux Systems Japan K.K.
    Copyright (C) 2005, 2011, 2020-2021  NEC Corporation
    Copyright (C) 1999, 2002, 2007  Silicon Graphics, Inc.
    Copyright (C) 1999, 2000, 2001, 2002  Mission Critical Linux, Inc.
    This program is free software, covered by the GNU General Public License,
    and you are welcome to change it and/or distribute copies of it under
    certain conditions.  Enter "help copying" to see the conditions.
    This program has absolutely no warranty.  Enter "help warranty" for details.
     
    GNU gdb (GDB) 7.6
    Copyright (C) 2013 Free Software Foundation, Inc.
    License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
    and "show warranty" for details.
    This GDB was configured as "x86_64-unknown-linux-gnu"...
    
    WARNING: kernel relocated [744MB]: patching 105274 gdb minimal_symbol values
    
          KERNEL: /usr/lib/debug/lib/modules/4.18.0-372.16.1.el8_6.x86_64/vmlinux
        DUMPFILE: /var/crash/127.0.0.1-2022-08-16-16:32:51/vmcore  [PARTIAL DUMP]
            CPUS: 2
            DATE: Tue Aug 16 16:32:41 -03 2022
          UPTIME: 22:44:27
    LOAD AVERAGE: 0.03, 0.03, 0.02
           TASKS: 170
        NODENAME: demo.example.local
         RELEASE: 4.18.0-372.16.1.el8_6.x86_64
         VERSION: #1 SMP Tue Jun 28 03:02:21 EDT 2022
         MACHINE: x86_64  (2112 Mhz)
          MEMORY: 4 GB
           PANIC: "sysrq: SysRq : Trigger a crash"
             PID: 32874
         COMMAND: "bash"
            TASK: ffff8931c7f4d200  [THREAD_INFO: ffff8931c7f4d200]
             CPU: 1
           STATE: TASK_RUNNING (SYSRQ)
    
    crash> help
    
    *              extend         log            rd             task           
    alias          files          mach           repeat         timer          
    ascii          foreach        mod            runq           tree           
    bpf            fuser          mount          search         union          
    bt             gdb            net            set            vm             
    btop           help           p              sig            vtop           
    dev            ipcs           ps             struct         waitq          
    dis            irq            pte            swap           whatis         
    eval           kmem           ptob           sym            wr             
    exit           list           ptov           sys            q              
    
    crash version: 7.3.1-5.el8   gdb version: 7.6
    For help on any command above, enter "help <command>".
    For help on input options, enter "help input".
    For help on output options, enter "help output".
    
    crash> log
    ...skipping...
    [81674.123533] 15922 pages in swap cache
    [81674.123534] Swap cache stats: add 170452, delete 154532, find 38295/42165
    [81674.123535] Free swap  = 964296kB
    [81674.123545] Total swap = 1048572kB
    [81674.123546] 1048443 pages RAM
    [81674.123547] 0 pages HighMem/MovableOnly
    [81674.123548] 93115 pages reserved
    [81674.123548] 0 pages hwpoisoned
    [81867.366572] sysrq: SysRq : Trigger a crash
    [81867.366731] Kernel panic - not syncing: sysrq triggered crash
                   
    [81867.366988] CPU: 1 PID: 32874 Comm: bash Kdump: loaded Not tainted 4.18.0-372.16.1.el8_6.x86_64 #1
    [81867.367139] Hardware name: Red Hat KVM, BIOS 1.11.0-2.el7 04/01/2014
    [81867.367280] Call Trace:
    [81867.367439]  dump_stack+0x41/0x60
    [81867.367582]  panic+0xe7/0x2ac
    [81867.369759]  ? printk+0x58/0x6f
    [81867.369905]  sysrq_handle_crash+0x11/0x20
    [81867.370037]  __handle_sysrq.cold.13+0x48/0xfb
    [81867.370169]  write_sysrq_trigger+0x2b/0x30
    [81867.370296]  proc_reg_write+0x39/0x60
    [81867.370439]  vfs_write+0xa5/0x1a0
    [81867.370568]  ksys_write+0x4f/0xb0
    [81867.370694]  do_syscall_64+0x5b/0x1a0
    [81867.370827]  entry_SYSCALL_64_after_hwframe+0x65/0xca
    [81867.370958] RIP: 0033:0x7f64ad4c55a8
    [81867.371088] Code: 89 02 48 c7 c0 ff ff ff ff eb b3 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 8d 05 f5 3f 2a 00 8b 00 85 c0 75 17 b8 01 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 58 c3 0f 1f 80 00 00 00 00 41 54 49 89 d4 55
    [81867.371372] RSP: 002b:00007fff0ea6b318 EFLAGS: 00000246 ORIG_RAX: 0000000000000001
    [81867.371512] RAX: ffffffffffffffda RBX: 0000000000000002 RCX: 00007f64ad4c55a8
    [81867.371659] RDX: 0000000000000002 RSI: 0000557c58a8f8e0 RDI: 0000000000000001
    [81867.371794] RBP: 0000557c58a8f8e0 R08: 000000000000000a R09: 00007f64ad525800
    [81867.371933] R10: 000000000000000a R11: 0000000000000246 R12: 00007f64ad7656e0
    [81867.372064] R13: 0000000000000002 R14: 00007f64ad760860 R15: 0000000000000002
    
    crash> bt
    PID: 32874  TASK: ffff8931c7f4d200  CPU: 1   COMMAND: "bash"
     #0 [ffffa72f80d9fcd0] machine_kexec at ffffffffaf86504e
     #1 [ffffa72f80d9fd28] __crash_kexec at ffffffffaf9a53ad
     #2 [ffffa72f80d9fdf0] panic at ffffffffaf8ed877
     #3 [ffffa72f80d9fe70] sysrq_handle_crash at ffffffffafdc4801
     #4 [ffffa72f80d9fe78] __handle_sysrq.cold.13 at ffffffffafdc50c8
     #5 [ffffa72f80d9fea8] write_sysrq_trigger at ffffffffafdc4f8b
     #6 [ffffa72f80d9feb8] proc_reg_write at ffffffffafbc3289
     #7 [ffffa72f80d9fed0] vfs_write at ffffffffafb40475
     #8 [ffffa72f80d9ff00] ksys_write at ffffffffafb406ef
     #9 [ffffa72f80d9ff38] do_syscall_64 at ffffffffaf80430b
    #10 [ffffa72f80d9ff50] entry_SYSCALL_64_after_hwframe at ffffffffb02000ad
        RIP: 00007f64ad4c55a8  RSP: 00007fff0ea6b318  RFLAGS: 00000246
        RAX: ffffffffffffffda  RBX: 0000000000000002  RCX: 00007f64ad4c55a8
        RDX: 0000000000000002  RSI: 0000557c58a8f8e0  RDI: 0000000000000001
        RBP: 0000557c58a8f8e0   R8: 000000000000000a   R9: 00007f64ad525800
        R10: 000000000000000a  R11: 0000000000000246  R12: 00007f64ad7656e0
        R13: 0000000000000002  R14: 00007f64ad760860  R15: 0000000000000002
        ORIG_RAX: 0000000000000001  CS: 0033  SS: 002b
    
    crash> ps
       PID    PPID  CPU       TASK        ST  %MEM     VSZ    RSS  COMM
    ...skipping...
    > 32874  32873   1  ffff8931c7f4d200  RU   0.1   28236   4256  bash
      41290      2   0  ffff8931c1cad200  ID   0.0       0      0  [kworker/u4:2]
      42813      2   0  ffff8931c0c5a900  ID   0.0       0      0  [kworker/0:3]
      43042      2   1  ffff89323bd90000  RU   0.0       0      0  [kworker/1:0]
      43043      2   1  ffff8931c2bcd200  ID   0.0       0      0  [kworker/u4:1]
      43045      2   1  ffff8931c4a35200  ID   0.0       0      0  [kworker/1:2]
      43048      1   1  ffff8931c5620000  IN   0.5  143424  32624  pmproxy
      43659      2   0  ffff8931c33a2900  ID   0.0       0      0  [kworker/0:0]
      43716      2   0  ffff8931c326d200  ID   0.0       0      0  [kworker/u4:0]
      43724    915   0  ffff8931c575d200  IN   0.0    7312   1848  sleep
      43725      2   0  ffff8931c2982900  ID   0.0       0      0  [kworker/0:1]
    
    crash> task 32874
    PID: 32874  TASK: ffff8931c7f4d200  CPU: 1   COMMAND: "bash"
    struct task_struct {
      thread_info = {
        flags = 2147483776, 
        status = 0
      }, 
      {
        {
          __state = 0
        }, 
        rh_kabi_hidden_742 = {
          state = 0
        }, 
        {<No data fields>}
      }, 
      stack = 0xffffa72f80d9c000, 
      {
        usage = {
          refs = {
            counter = 1
          }
        }, 
        rh_kabi_hidden_751 = {
          usage = {
            counter = 1
          }
        }, 
        {<No data fields>}
      }, 
    ...skipping...
    
    crash> files
    PID: 32874  TASK: ffff8931c7f4d200  CPU: 1   COMMAND: "bash"
    ROOT: /    CWD: /root
     FD       FILE            DENTRY           INODE       TYPE PATH
      0 ffff8931c2f92b00 ffff8931c8137d80 ffff8931fb280cd0 CHR  /dev/pts/0
      1 ffff8931c585a200 ffff8931c3a8d9c0 ffff8931c8311f90 REG  /proc/sysrq-trigger
      2 ffff8931c2f92b00 ffff8931c8137d80 ffff8931fb280cd0 CHR  /dev/pts/0
      3 ffff8931c54bd700 ffff8931c8029cc0 ffff8931c801ebb0 REG  /var/lib/sss/mc/passwd
      4 ffff8931c54bd200 ffff8931c811f240 ffff8931c8266970 SOCK UNIX
     10 ffff8931c2f92b00 ffff8931c8137d80 ffff8931fb280cd0 CHR  /dev/pts/0
    255 ffff8931c2f92b00 ffff8931c8137d80 ffff8931fb280cd0 CHR  /dev/pts/0
    
    crash> dis -r ffffffffaf9a53ad
    0xffffffffaf9a5340 <__crash_kexec>:     nopl   0x0(%rax,%rax,1) [FTRACE NOP]
    0xffffffffaf9a5345 <__crash_kexec+5>:   push   %rbp
    0xffffffffaf9a5346 <__crash_kexec+6>:   push   %rbx
    0xffffffffaf9a5347 <__crash_kexec+7>:   mov    %rdi,%rbx
    0xffffffffaf9a534a <__crash_kexec+10>:  mov    $0xffffffffb1435e40,%rdi
    0xffffffffaf9a5351 <__crash_kexec+17>:  sub    $0xb0,%rsp
    0xffffffffaf9a5358 <__crash_kexec+24>:  mov    %gs:0x28,%rax
    0xffffffffaf9a5361 <__crash_kexec+33>:  mov    %rax,0xa8(%rsp)
    0xffffffffaf9a5369 <__crash_kexec+41>:  xor    %eax,%eax
    0xffffffffaf9a536b <__crash_kexec+43>:  callq  0xffffffffb01a2020 <mutex_trylock>
    0xffffffffaf9a5370 <__crash_kexec+48>:  test   %eax,%eax
    0xffffffffaf9a5372 <__crash_kexec+50>:  je     0xffffffffaf9a53b9 <__crash_kexec+121>
    0xffffffffaf9a5374 <__crash_kexec+52>:  cmpq   $0x0,0x2401e7c(%rip)        # 0xffffffffb1da71f8
    0xffffffffaf9a537c <__crash_kexec+60>:  je     0xffffffffaf9a53ad <__crash_kexec+109>
    0xffffffffaf9a537e <__crash_kexec+62>:  test   %rbx,%rbx
    0xffffffffaf9a5381 <__crash_kexec+65>:  je     0xffffffffaf9a53da <__crash_kexec+154>
    0xffffffffaf9a5383 <__crash_kexec+67>:  mov    %rsp,%rbp
    0xffffffffaf9a5386 <__crash_kexec+70>:  mov    $0x15,%ecx
    0xffffffffaf9a538b <__crash_kexec+75>:  mov    %rbx,%rsi
    0xffffffffaf9a538e <__crash_kexec+78>:  mov    %rbp,%rdi
    0xffffffffaf9a5391 <__crash_kexec+81>:  rep movsq %ds:(%rsi),%es:(%rdi)
    0xffffffffaf9a5394 <__crash_kexec+84>:  callq  0xffffffffaf9a4e00 <crash_save_vmcoreinfo>
    0xffffffffaf9a5399 <__crash_kexec+89>:  mov    %rbp,%rdi
    0xffffffffaf9a539c <__crash_kexec+92>:  callq  0xffffffffaf857950 <machine_crash_shutdown>
    0xffffffffaf9a53a1 <__crash_kexec+97>:  mov    0x2401e50(%rip),%rdi        # 0xffffffffb1da71f8
    0xffffffffaf9a53a8 <__crash_kexec+104>: callq  0xffffffffaf864e90 <machine_kexec>
    0xffffffffaf9a53ad <__crash_kexec+109>: mov    $0xffffffffb1435e40,%rdi
    
    crash> kmem -i
                     PAGES        TOTAL      PERCENTAGE
        TOTAL MEM   955328       3.6 GB         ----
             FREE   849606       3.2 GB   88% of TOTAL MEM
             USED   105722       413 MB   11% of TOTAL MEM
           SHARED     8237      32.2 MB    0% of TOTAL MEM
          BUFFERS        0            0    0% of TOTAL MEM
           CACHED    42874     167.5 MB    4% of TOTAL MEM
             SLAB    11013        43 MB    1% of TOTAL MEM
    
       TOTAL HUGE        0            0         ----
        HUGE FREE        0            0    0% of TOTAL HUGE
    
       TOTAL SWAP   262143      1024 MB         ----
        SWAP USED    21069      82.3 MB    8% of TOTAL SWAP
        SWAP FREE   241074     941.7 MB   91% of TOTAL SWAP
    
     COMMIT LIMIT   739807       2.8 GB         ----
        COMMITTED   107082     418.3 MB   14% of TOTAL LIMIT

### Install and create sosreport

    [root@demo ~]# rpm -qa | grep sos
    sos-4.2-20.el8_6.noarch
    
    [root@demo ~]# sos report --allow-system-changes
    
    [root@demo ~]# ls -ltr /var/tmp/
    total 37188
    -rw-------.  1 root root 18976176 ago 19 09:57 sosreport-demo-2022-08-19-wvihyks.tar.xz
    -rw-r--r--.  1 root root       65 ago 19 09:57 sosreport-demo-2022-08-19-wvihyks.tar.xz.sha256

### Basic sosreport overview

    [root@demo ~]# dnf install http://people.redhat.com/rsawhill/rpms/latest-rsawaroha-release.rpm
    
    [root@demo ~]# dnf install xsos rsar
    
    [root@demo ~]# tar -Jxvf /var/tmp/sosreport-demo-2022-08-19-wvihyks.tar.xz -C /var/tmp/
    
    [root@demo ~]# xsos -ay /var/tmp/sosreport-demo-2022-08-19-wvihyks
    
    DMIDECODE
      BIOS:
        Vend: SeaBIOS
        Vers: 1.11.0-2.el7
        Date: 04/01/2014
        BIOS Rev: 0.0
        FW Rev:  
      System:
        Mfr:  Red Hat
        Prod: KVM
        Vers: RHEL-7.4.0 PC (Q35 + ICH9, 2009)
        Ser:  Not Specified
        UUID: f459afe5-6d04-42ae-8b4d-7d81b94c5414
      CPU:
        2 of 2 CPU sockets populated, 1 cores/1 threads per CPU
        2 total cores, 2 total threads
        Mfr:  Red Hat
        Fam: 
        Freq: 2000 MHz
        Vers: RHEL-7.4.0 PC (Q35 + ICH9, 2009)
      Memory:
        Total: 4096 MiB (4 GiB)
        DIMMs: 1 of 1 populated
        MaxCapacity: 4096 MiB (4 GiB / 0.00 TiB)
    
    OS
      Hostname: demo.example.local
      Distro:   [redhat-release] Red Hat Enterprise Linux release 8.6 (Ootpa)
                [os-release] Red Hat Enterprise Linux 8.6 (Ootpa) 8.6 (Ootpa)
      RHN:      (missing)
      RHSM:     hostname = satellite.example.local
                proxy_hostname =
      YUM:      3 enabled plugins: debuginfo-install, product-id, subscription-manager
      SELinux:  enforcing  (default enforcing)
    ...skipping...
    
    [root@demo ~]# ls /var/tmp/sosreport-demo-2022-08-19-wvihyks
    boot       df           etc       installed-rpms  lib    lspci    pmstat  pstree  run           sos_reports  uname   var
    chkconfig  dmidecode    free      ip_addr         lsmod  mount    proc    root    sos_commands  sos_strings  uptime  version.txt
    date       environment  hostname  last            lsof   netstat  ps      route   sos_logs      sys          usr     vgdisplay
    
    [root@demo ~]# ls /var/tmp/sosreport-demo-2022-08-19-wvihyks/sos_commands/
    alternatives  console       dnf              hardware  kvm        md              numa     processor  scsi                  sysvipc    yum
    ata           cron          dracut           host      libraries  memory          pam      python     selinux               targetcli
    auditd        crypto        filesys          i18n      libvirt    multipath       pci      redis      services              tuned
    block         date          firewalld        iscsi     login      networking      pcp      rpm        subscription_manager  vdo
    boot          dbus          firewall_tables  kdump     logrotate  networkmanager  perl     rpmostree  sunrpc                vhostmd
    cgroups       devicemapper  gluster          kernel    logs       nfs             podman   runc       systemd               virsh
    cockpit       devices       grub2            keyutils  lvm2       nis             process  sar        systemtap             xfs
    
    [root@demo ~]# ls /var/tmp/sosreport-demo-2022-08-19-wvihyks/var/log/
    anaconda  dnf.librepo.log  dnf.rpm.log      kdump.log          messages-20220609  redis   secure-20220602  spooler
    audit     dnf.log          firewalld        maillog            messages-20220810  rhsm    secure-20220609  sssd
    boot.log  dnf.log.1        glusterfs        messages           messages-20220817  sa      secure-20220810  tuned
    cron      dnf.log.2        insights-client  messages-20220602  pcp                secure  secure-20220817

---

### Performance Troubleshooting - Examples:
#### Before begin:

 1. #### Know and understand well each component of your environment/system (hardware, firmware, software, etc.)
2.  #### Set the baseline based on each environment of what is standard and acceptable prior to any analysis or issue
3.  #### Pre-load test to understand the behavior of each environment/system
4.  #### Understand the utilization, saturation and error values ​​of each environment/system
5.  #### Understand the relationship between different processes and components, and how they affect each environment/system metric

### Network load/failure simulations

#### Show Queue Discipline

    [root@demo ~]# tc qdisc show
    qdisc noqueue 0: dev lo root refcnt 2 
    qdisc fq_codel 0: dev enp1s0 root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64 

#### Simulating a Fixed Delay

    tc qdisc add dev enp1s0 root netem delay 100ms

#### Simulating Normally Distributed Delays

    tc qdisc add dev enp1s0 root netem delay 100ms 50ms distribution normal

#### Simulating Packet Loss

    tc qdisc add dev enp1s0 root netem loss 30%

#### Simulating Packet Loss with Probability

    tc qdisc add dev enp1s0 root netem loss 30% 50%

#### Simulating Packet Duplication

    tc qdisc add dev enp1s0 root duplicate 50%

#### Simulating Packet Corruption

    tc qdisc add dev enp1s0 root netem corrupt 30%

#### Limiting the Transfer Rate

    tc qdisc add dev enp1s0 root netem rate 10Mbit

#### Delete the qdisc

    tc qdisc delete dev enp1s0 root


### Simulating CPU, memory and disk workload

    [root@demo ~]# rpm -qa | grep stress
    stress-ng-0.13.10-1.el8.x86_64
    
    [root@demo ~]# stress-ng -c 2 -l 100 --timeout 15
    stress-ng: info:  [118293] setting to a 15 second run per stressor
    stress-ng: info:  [118293] dispatching hogs: 2 cpu
    stress-ng: info:  [118293] successful run completed in 15.00s
    
    [root@demo ~]# stress-ng -m 1 --vm-bytes 3.2G --vm-keep --timeout 15
    stress-ng: info:  [118346] setting to a 15 second run per stressor
    stress-ng: info:  [118346] dispatching hogs: 1 vm
    stress-ng: info:  [118346] successful run completed in 15.15s
    
    [root@demo ~]# dd if=/dev/zero of=./teste bs=1k count=2000000
    2000000+0 records in
    2000000+0 records out
    2048000000 bytes (2,0 GB, 1,9 GiB) copied, 21,1111 s, 97,0 MB/s
    
    # fio --randrepeat=1 --ioengine=libaio --direct=1 --gtod_reduce=1 --name=test --filename=random_read_write.fio --bs=4k --iodepth=64 --size=5G --readwrite=randrw --rwmixread=75
    test: (g=0): rw=randrw, bs=(R) 4096B-4096B, (W) 4096B-4096B, (T) 4096B-4096B, ioengine=libaio, iodepth=64
    fio-3.7
    Starting 1 process
    Jobs: 1 (f=1): [m(1)][100.0%][r=80.1MiB/s,w=26.6MiB/s][r=20.5k,w=6814 IOPS][eta 00m:00s]
    test: (groupid=0, jobs=1): err= 0: pid=15851: Fri Aug 19 16:09:52 2022
       read: IOPS=50.7k, BW=198MiB/s (208MB/s)(3837MiB/19380msec)
       bw (  KiB/s): min=69472, max=273984, per=100.00%, avg=205411.24, stdev=70600.54, samples=38
       iops        : min=17368, max=68496, avg=51352.76, stdev=17650.16, samples=38
      write: IOPS=16.9k, BW=66.2MiB/s (69.4MB/s)(1283MiB/19380msec)
       bw (  KiB/s): min=23840, max=91120, per=100.00%, avg=68651.13, stdev=23560.99, samples=38
       iops        : min= 5960, max=22780, avg=17162.76, stdev=5890.25, samples=38
      cpu          : usr=16.84%, sys=51.13%, ctx=189346, majf=0, minf=29
      IO depths    : 1=0.1%, 2=0.1%, 4=0.1%, 8=0.1%, 16=0.1%, 32=0.1%, >=64=100.0%
         submit    : 0=0.0%, 4=100.0%, 8=0.0%, 16=0.0%, 32=0.0%, 64=0.0%, >=64=0.0%
         complete  : 0=0.0%, 4=100.0%, 8=0.0%, 16=0.0%, 32=0.0%, 64=0.1%, >=64=0.0%
         issued rwts: total=982350,328370,0,0 short=0,0,0,0 dropped=0,0,0,0
         latency   : target=0, window=0, percentile=100.00%, depth=64
    
    Run status group 0 (all jobs):
       READ: bw=198MiB/s (208MB/s), 198MiB/s-198MiB/s (208MB/s-208MB/s), io=3837MiB (4024MB), run=19380-19380msec
      WRITE: bw=66.2MiB/s (69.4MB/s), 66.2MiB/s-66.2MiB/s (69.4MB/s-69.4MB/s), io=1283MiB (1345MB), run=19380-19380msec
    
    Disk stats (read/write):
        dm-2: ios=978719/327335, merge=0/0, ticks=821461/96582, in_queue=919952, util=99.31%, aggrios=983671/338127, aggrmerge=0/0, aggrticks=834551/123768, aggrin_queue=960986, aggrutil=99.18%
        dm-0: ios=983671/338127, merge=0/0, ticks=834551/123768, in_queue=960986, util=99.18%, aggrios=983670/338028, aggrmerge=1/99, aggrticks=816020/111708, aggrin_queue=927728, aggrutil=99.37%
      nvme0n1: ios=983670/338028, merge=1/99, ticks=816020/111708, in_queue=927728, util=99.37%

### CPU, memory, disk and networking analysis examples
#### Checking tooling

    [root@demo ~]# ping -c4 www.google.com.br
    PING www.google.com.br (172.253.115.94) 56(84) bytes of data.
    64 bytes from bg-in-f94.1e100.net (172.253.115.94): icmp_seq=1 ttl=99 time=128 ms
    64 bytes from bg-in-f94.1e100.net (172.253.115.94): icmp_seq=2 ttl=99 time=124 ms
    64 bytes from bg-in-f94.1e100.net (172.253.115.94): icmp_seq=3 ttl=99 time=134 ms
    64 bytes from bg-in-f94.1e100.net (172.253.115.94): icmp_seq=4 ttl=99 time=123 ms
    
    --- www.google.com.br ping statistics ---
    4 packets transmitted, 4 received, 0% packet loss, time 3005ms
    rtt min/avg/max/mdev = 122.845/127.274/133.620/4.190 ms
    
    # ethtool enp11s0u1
    Settings for enp11s0u1:
    	Supported ports: [ TP MII ]
    	Supported link modes:   10baseT/Half 10baseT/Full 
    	                        100baseT/Half 100baseT/Full 
    	                        1000baseT/Half 1000baseT/Full 
    	Supported pause frame use: No
    	Supports auto-negotiation: Yes
    	Supported FEC modes: Not reported
    	Advertised link modes:  10baseT/Half 10baseT/Full 
    	                        100baseT/Half 100baseT/Full 
    	                        1000baseT/Full 
    	Advertised pause frame use: Symmetric Receive-only
    	Advertised auto-negotiation: Yes
    	Advertised FEC modes: Not reported
    	Link partner advertised link modes:  10baseT/Half 10baseT/Full 
    	                                     100baseT/Half 100baseT/Full 
    	                                     1000baseT/Full 
    	Link partner advertised pause frame use: Symmetric Receive-only
    	Link partner advertised auto-negotiation: Yes
    	Link partner advertised FEC modes: Not reported
    	Speed: 1000Mb/s
    	Duplex: Full
    	Port: MII
    	PHYAD: 32
    	Transceiver: internal
    	Auto-negotiation: on
    	Supports Wake-on: pumbg
    	Wake-on: d
    	Current message level: 0x00007fff (32767)
    			       drv probe link timer ifdown ifup rx_err tx_err tx_queued intr tx_done rx_status pktdata hw wol
    	Link detected: yes
    
    # ethtool -k enp11s0u1
    Features for enp11s0u1:
    rx-checksumming: on
    tx-checksumming: on
    	tx-checksum-ipv4: on
    	tx-checksum-ip-generic: off [fixed]
    	tx-checksum-ipv6: on
    	tx-checksum-fcoe-crc: off [fixed]
    	tx-checksum-sctp: off [fixed]
    scatter-gather: on
    	tx-scatter-gather: on
    	tx-scatter-gather-fraglist: on
    tcp-segmentation-offload: on
    	tx-tcp-segmentation: on
    	tx-tcp-ecn-segmentation: off [fixed]
    	tx-tcp6-segmentation: on
    	tx-tcp-mangleid-segmentation: off
    udp-fragmentation-offload: off [fixed]
    generic-segmentation-offload: on
    generic-receive-offload: on
    large-receive-offload: off [fixed]
    rx-vlan-offload: on
    tx-vlan-offload: on
    ntuple-filters: off [fixed]
    receive-hashing: off [fixed]
    highdma: off [fixed]
    rx-vlan-filter: off [fixed]
    vlan-challenged: off [fixed]
    tx-lockless: off [fixed]
    netns-local: off [fixed]
    tx-gso-robust: off [fixed]
    tx-fcoe-segmentation: off [fixed]
    tx-gre-segmentation: off [fixed]
    tx-ipip-segmentation: off [fixed]
    tx-sit-segmentation: off [fixed]
    tx-udp_tnl-segmentation: off [fixed]
    fcoe-mtu: off [fixed]
    tx-nocache-copy: off
    loopback: off [fixed]
    rx-fcs: off [fixed]
    rx-all: off [fixed]
    tx-vlan-stag-hw-insert: off [fixed]
    rx-vlan-stag-hw-parse: off [fixed]
    rx-vlan-stag-filter: off [fixed]
    busy-poll: off [fixed]
    tx-gre-csum-segmentation: off [fixed]
    tx-udp_tnl-csum-segmentation: off [fixed]
    tx-gso-partial: off [fixed]
    tx-sctp-segmentation: off [fixed]
    rx-gro-hw: off [fixed]
    l2-fwd-offload: off [fixed]
    hw-tc-offload: off [fixed]
    rx-udp_tunnel-port-offload: off [fixed]
    
    [root@demo ~]# netstat -s
    Ip:
        Forwarding: 2
        3109429 total packets received
        163 with invalid addresses
        0 forwarded
        0 incoming packets discarded
        3103122 incoming packets delivered
        3737699 requests sent out
        1 outgoing packets dropped
        178 dropped because of missing route
        385820 fragments received ok
        8873860 fragments created
    Icmp:
        111 ICMP messages received
        0 input ICMP message failed
        ICMP input histogram:
            echo requests: 49
            echo replies: 62
        182 ICMP messages sent
        0 ICMP messages failed
        ICMP output histogram:
            destination unreachable: 3
            echo requests: 130
            echo replies: 49
    IcmpMsg:
            InType0: 62
            InType8: 49
            OutType0: 49
            OutType3: 3
            OutType8: 130
    Tcp:
        1740 active connection openings
        73 passive connection openings
        0 failed connection attempts
        17 connection resets received
        10 connections established
        2888465 segments received
        106828701 segments sent out
        282 segments retransmitted
        1 bad segments received
        3427 resets sent
    Udp:
        214543 packets received
        2 packets to unknown port received
        0 packet receive errors
        600373 packets sent
        0 receive buffer errors
        1 send buffer errors
    UdpLite:
    TcpExt:
        56 TCP sockets finished time wait in fast timer
        1 packets rejected in established connections because of timestamp
        11685 delayed acks sent
        14 delayed acks further delayed because of locked socket
        Quick ack mode was activated 62 times
        288274 packet headers predicted
        216120 acknowledgments not containing data payload received
        1938402 predicted acknowledgments
        TCPSackRecovery: 31
        TCPDSACKUndo: 2
        7 congestion windows recovered without slow start after partial ack
        TCPLostRetransmit: 52
        4 timeouts in loss state
        51 fast retransmits
        38 retransmits in slow start
        TCPTimeouts: 36
        TCPLossProbes: 147
        TCPLossProbeRecovery: 29
        TCPSackRecoveryFail: 9
        TCPBacklogCoalesce: 600218
        TCPDSACKOldSent: 62
        TCPDSACKRecv: 56
        1671 connections reset due to unexpected data
        4 connections reset due to early user close
        1 connections aborted due to timeout
        6 times unable to send RST due to no memory
        TCPDSACKIgnoredNoUndo: 22
        TCPSackMerged: 20
        TCPSackShiftFallback: 44
        IPReversePathFilter: 57
        TCPRcvCoalesce: 16406
        TCPOFOQueue: 416
        TCPChallengeACK: 1
        TCPSYNChallenge: 1
        TCPSpuriousRtxHostQueues: 9
        TCPAutoCorking: 300823
        TCPFromZeroWindowAdv: 205
        TCPToZeroWindowAdv: 205
        TCPWantZeroWindowAdv: 271
        TCPSynRetrans: 7
        TCPOrigDataSent: 106710996
        TCPHystartTrainDetect: 41
        TCPHystartTrainCwnd: 3488
        TCPHystartDelayDetect: 1
        TCPHystartDelayCwnd: 29
        TCPKeepAlive: 8329
        TCPDelivered: 106708303
        TCPAckCompressed: 403
    IpExt:
        InBcastPkts: 10
        InOctets: 1024918700
        OutOctets: 167146767096
        InBcastOctets: 3196
        InNoECTPkts: 3109515

---

#### In the server machine

    # iperf3 -s -p 19766
    -----------------------------------------------------------
    Server listening on 19766
    -----------------------------------------------------------

#### In the client machine

    [root@demo ~]# iperf3 -c 192.168.1.1 -p 19766
    Connecting to host 192.168.1.1, port 19766
    [  5] local 192.168.1.27 port 55096 connected to 192.168.1.1 port 19766
    [ ID] Interval           Transfer     Bitrate         Retr  Cwnd
    [  5]   0.00-1.00   sec  2.95 GBytes  25.3 Gbits/sec    0   1.42 MBytes       
    [  5]   1.00-2.00   sec  2.78 GBytes  23.9 Gbits/sec    0   2.51 MBytes       
    [  5]   2.00-3.00   sec  3.07 GBytes  26.4 Gbits/sec    0   2.51 MBytes       
    [  5]   3.00-4.00   sec  3.27 GBytes  28.1 Gbits/sec    0   2.76 MBytes       
    [  5]   4.00-5.00   sec  3.03 GBytes  26.0 Gbits/sec    0   2.76 MBytes       
    [  5]   5.00-6.00   sec  3.24 GBytes  27.9 Gbits/sec    0   2.76 MBytes       
    [  5]   6.00-7.00   sec  3.02 GBytes  26.0 Gbits/sec    0   3.04 MBytes       
    [  5]   7.00-8.00   sec  3.21 GBytes  27.6 Gbits/sec    0   3.04 MBytes       
    [  5]   8.00-9.00   sec  2.91 GBytes  25.0 Gbits/sec    0   3.04 MBytes       
    [  5]   9.00-10.00  sec  3.01 GBytes  25.9 Gbits/sec    0   3.04 MBytes       
    - - - - - - - - - - - - - - - - - - - - - - - - -
    [ ID] Interval           Transfer     Bitrate         Retr
    [  5]   0.00-10.00  sec  30.5 GBytes  26.2 Gbits/sec    0             sender
    [  5]   0.00-10.00  sec  30.5 GBytes  26.2 Gbits/sec                  receiver
    
    iperf Done.

---

#### In the server machine

    # qperf

#### In the client machine

    [root@demo ~]# qperf -v 192.168.1.1 --ip_port 19766 --time 5 tcp_bw tcp_lat udp_bw udp_lat
    tcp_bw:
        bw              =    3.49 GB/sec
        msg_rate        =    53.2 K/sec
        port            =  19,766 
        time            =       5 sec
        send_cost       =     238 ms/GB
        recv_cost       =    1.29 sec/GB
        send_cpus_used  =      83 % cpus
        recv_cpus_used  =     450 % cpus
    tcp_lat:
        latency        =    20.6 us
        msg_rate       =    48.6 K/sec
        port           =  19,766 
        time           =       5 sec
        loc_cpus_used  =    48.8 % cpus
        rem_cpus_used  =     346 % cpus
    udp_bw:
        send_bw         =     742 MB/sec
        recv_bw         =     727 MB/sec
        msg_rate        =    22.2 K/sec
        port            =  19,766 
        time            =       5 sec
        send_cost       =     933 ms/GB
        recv_cost       =    5.25 sec/GB
        send_cpus_used  =    69.2 % cpus
        recv_cpus_used  =     382 % cpus
    udp_lat:
        latency        =      22 us
        msg_rate       =    45.4 K/sec
        port           =  19,766 
        time           =       5 sec
        loc_cpus_used  =    43.6 % cpus
        rem_cpus_used  =     397 % cpus

---

#### In the server machine

    [root@demo ~]# tcpdump -i enp1s0 port not 22 and port not 3260 and host 192.168.1.1 -vv
    dropped privs to tcpdump
    tcpdump: listening on enp1s0, link-type EN10MB (Ethernet), capture size 262144 bytes
    15:55:33.622720 IP (tos 0x0, ttl 64, id 20676, offset 0, flags [DF], proto ICMP (1), length 84)
        _gateway > demo: ICMP echo request, id 12430, seq 1, length 64
    15:55:33.622856 IP (tos 0x0, ttl 64, id 58321, offset 0, flags [none], proto ICMP (1), length 84)
        demo > _gateway: ICMP echo reply, id 12430, seq 1, length 64
    15:55:33.623766 IP (tos 0x0, ttl 64, id 64332, offset 0, flags [DF], proto UDP (17), length 71)
        demo.39409 > _gateway.domain: [bad udp cksum 0x83b1 -> 0x554d!] 2282+ PTR? 27.1.168.192.in-addr.arpa. (43)
    15:55:33.623883 IP (tos 0x0, ttl 64, id 35667, offset 0, flags [DF], proto UDP (17), length 89)
        _gateway.domain > demo.39409: [bad udp cksum 0x83c3 -> 0xdf0e!] 2282* q: PTR? 27.1.168.192.in-addr.arpa. 1/0/0 27.1.168.192.in-addr.arpa. PTR demo. (61)
    15:55:33.624039 IP (tos 0x0, ttl 64, id 64333, offset 0, flags [DF], proto UDP (17), length 70)
        demo.56391 > _gateway.domain: [bad udp cksum 0x83b0 -> 0xba92!] 22674+ PTR? 1.1.168.192.in-addr.arpa. (42)
    15:55:33.773438 IP (tos 0x0, ttl 64, id 35753, offset 0, flags [DF], proto UDP (17), length 70)
        _gateway.domain > demo.56391: [bad udp cksum 0x83b0 -> 0x3a10!] 22674 ServFail q: PTR? 1.1.168.192.in-addr.arpa. 0/0/0 (42)

#### In the client machine

    # ping -c1 demo.example.local
    PING demo (192.168.1.27) 56(84) bytes of data.
    64 bytes from demo (192.168.1.27): icmp_seq=1 ttl=64 time=0.251 ms
    
    --- demo ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 0.251/0.251/0.251/0.000 ms

---

    [root@demo ~]# iptraf-ng
    
    [root@demo ~]# perf stat ls
    anaconda-ks.cfg  demo-certs  tshoot-tools
    
     Performance counter stats for 'ls':
    
                  1,26 msec task-clock                #    0,672 CPUs utilized          
                     0      context-switches          #    0,000 /sec                   
                     0      cpu-migrations            #    0,000 /sec                   
                    95      page-faults               #   75,210 K/sec                  
       <not supported>      cycles                                                      
       <not supported>      instructions                                                
       <not supported>      branches                                                    
       <not supported>      branch-misses                                               
    
           0,001878325 seconds time elapsed
    
           0,000172000 seconds user
           0,001759000 seconds sys
    
    [root@demo ~]# free -ht
                  total        used        free      shared  buff/cache   available
    Mem:          3,6Gi       395Mi       2,4Gi       5,0Mi       903Mi       3,0Gi
    Swap:         1,0Gi       121Mi       902Mi
    Total:        4,6Gi       516Mi       3,3Gi
    
    [root@demo ~]# top
    top - 17:55:31 up 2 days, 25 min,  2 users,  load average: 0,01, 0,02, 0,03
    Tasks: 186 total,   2 running, 184 sleeping,   0 stopped,   0 zombie
    %Cpu0  :  0,3 us,  0,0 sy,  0,0 ni, 99,7 id,  0,0 wa,  0,0 hi,  0,0 si,  0,0 st
    %Cpu1  :  0,0 us,  0,3 sy,  0,0 ni, 96,0 id,  3,3 wa,  0,3 hi,  0,0 si,  0,0 st
    MiB Mem :   3731,8 total,   1419,7 free,    529,1 used,   1783,0 buff/cache
    MiB Swap:   1024,0 total,    906,1 free,    117,9 used.   2887,7 avail Mem 
    
        PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND                                                                       
     128858 root      20   0       0      0      0 R   0,3   0,0   0:00.02 kworker/1:3-xfs-buf/dm-0                                                      
     128859 root      20   0  275232   4704   4048 R   0,3   0,1   0:00.03 top                                                                           
          1 root      20   0  243712  13704   7496 S   0,0   0,4   0:24.68 systemd                                                                       
          2 root      20   0       0      0      0 S   0,0   0,0   0:00.15 kthreadd                                                                      
          3 root       0 -20       0      0      0 I   0,0   0,0   0:00.00 rcu_gp                       
    ...skipping...
    
    [root@demo ~]# systemd-cgtop
    Control Group                                                                                                 Tasks   %CPU   Memory  Input/s Output/s
    /                                                                                                               227    2.0     2.2G        -        -
    /user.slice                                                                                                      12    1.7     1.5G        -        -
    /system.slice                                                                                                    80    0.3   422.9M        -        -
    /system.slice/tuned.service                                                                                       5    0.2    15.7M        -        -
    /system.slice/redis.service                                                                                       4    0.1   146.0M        -        -
    /system.slice/rhsm.service                                                                                        2    0.0    24.5M        -        -
    /system.slice/pmproxy.service                                                                                     1    0.0    30.8M        -        -
    /system.slice/multipathd.service                                                                                  7    0.0    11.5M        -        -
    /system.slice/NetworkManager.service                                                                              3    0.0     4.6M        -        -
    /system.slice/rsyslog.service                                                                                     3    0.0     2.9M        -        -
    /system.slice/sssd.service                                                                                        3    0.0    11.7M        -        -
    /init.scope                                                                                                       1      -    26.4M        -        -
    /system.slice/auditd.service                                                                                      4      -     1.9M        -        -
    /system.slice/boot.mount                                                                                          -      -     4.0K        -        -
    /system.slice/cockpit-wsinstance-http.socket                                                                      -      -     4.0K        -        -
    /system.slice/cockpit-wsinstance-https-factory.socket                                                             -      -     4.0K        -        -
    /system.slice/cockpit.service                                                                                     7      -     2.5M        -        -
    /system.slice/cockpit.socket                                                                                      -      -    60.0K        -        -
    /system.slice/crond.service                                                                                       1      -     1.1M        -        -
    /system.slice/dbus.service                                                                                        2      -     1.9M        -        -
    /system.slice/dev-hugepages.mount                                                                                 -      -     4.0K        -        -
    /system.slice/dev-mapper-VG_01\x2dswap.swap                                                                       -      -    56.0K        -        -
    /system.slice/dev-mqueue.mount                                                                                    -      -     4.0K        -        -
    /system.slice/firewalld.service                                                                                   2      -    23.1M        -        -
    /system.slice/gssproxy.service                                                                                    6      -  1008.0K        -        -
    /system.slice/irqbalance.service                                                                                  2      -   920.0K        -        -
    /system.slice/iscsid.service                                                                                      1      -    13.4M        -        -
    /system.slice/ksmtuned.service                                                                                    2      -     6.3M        -        -
    /system.slice/osbuild-composer.socket                                                                             -      -     4.0K        -        -
    /system.slice/pmcd.service                                                                                        6      -    12.9M        -        -

    [root@demo ~]# iostat -cdyx 1 1
    Linux 4.18.0-372.19.1.el8_6.x86_64 (demo.example.local) 	19/08/2022 	_x86_64_	(2 CPU)
    
    avg-cpu:  %user   %nice %system %iowait  %steal   %idle
               0,00    0,00    0,00    0,00    0,00    0,00
    
    Device            r/s     w/s     rkB/s     wkB/s   rrqm/s   wrqm/s  %rrqm  %wrqm r_await w_await aqu-sz rareq-sz wareq-sz  svctm  %util
    vda              0,00    0,00      0,00      0,00     0,00     0,00   0,00   0,00    0,00    0,00   0,00     0,00     0,00   0,00   0,00
    scd0             0,00    0,00      0,00      0,00     0,00     0,00   0,00   0,00    0,00    0,00   0,00     0,00     0,00   0,00   0,00
    dm-0             0,00    0,00      0,00      0,00     0,00     0,00   0,00   0,00    0,00    0,00   0,00     0,00     0,00   0,00   0,00
    dm-1             0,00    0,00      0,00      0,00     0,00     0,00   0,00   0,00    0,00    0,00   0,00     0,00     0,00   0,00   0,00
    sda              0,00    0,00      0,00      0,00     0,00     0,00   0,00   0,00    0,00    0,00   0,00     0,00     0,00   0,00   0,00
    sdb              0,00    0,00      0,00      0,00     0,00     0,00   0,00   0,00    0,00    0,00   0,00     0,00     0,00   0,00   0,00
    dm-2             0,00    0,00      0,00      0,00     0,00     0,00   0,00   0,00    0,00    0,00   0,00     0,00     0,00   0,00   0,00
    dm-3             0,00    0,00      0,00      0,00     0,00     0,00   0,00   0,00    0,00    0,00   0,00     0,00     0,00   0,00   0,00
    
    [root@demo ~]# mpstat -P ALL 1 1
    Linux 4.18.0-372.19.1.el8_6.x86_64 (demo.example.local) 	19/08/2022 	_x86_64_	(2 CPU)
    
    16:31:09     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
    16:31:10     all    1,49    0,00    1,00   13,43    0,00    0,00    0,00    0,00    0,00   84,08
    16:31:10       0    1,98    0,00    0,99   26,73    0,00    0,00    0,00    0,00    0,00   70,30
    16:31:10       1    1,00    0,00    1,00    0,00    0,00    0,00    0,00    0,00    0,00   98,00
    
    Average:     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
    Average:     all    1,49    0,00    1,00   13,43    0,00    0,00    0,00    0,00    0,00   84,08
    Average:       0    1,98    0,00    0,99   26,73    0,00    0,00    0,00    0,00    0,00   70,30
    Average:       1    1,00    0,00    1,00    0,00    0,00    0,00    0,00    0,00    0,00   98,00
    
    [root@demo ~]# iotop
    Total DISK READ :	0.00 B/s | Total DISK WRITE :       0.00 B/s
    Actual DISK READ:	0.00 B/s | Actual DISK WRITE:       0.00 B/s
        TID  PRIO  USER     DISK READ DISK WRITE>    COMMAND                                                                                             
          1 be/4 root        0.00 B/s    0.00 B/s systemd --switched-root --system --deserialize 18
          2 be/4 root        0.00 B/s    0.00 B/s [kthreadd]
          3 be/0 root        0.00 B/s    0.00 B/s [rcu_gp]
          4 be/0 root        0.00 B/s    0.00 B/s [rcu_par_gp]
    ...skipping...
    
    [root@demo ~]# iftop
                                 12,5Kb                        25,0Kb                        37,5Kb                        50,0Kb                  62,5Kb
    └────────────────────────────┴─────────────────────────────┴─────────────────────────────┴─────────────────────────────┴─────────────────────────────
    demo                                                         => _gateway                                                      1,59Kb  2,85Kb  2,85Kb
                                                                 <=                                                                608b    981b    981b
    demo                                                         => dns                                                              0b     56b     56b
                                                                 <=                                                                  0b    102b    102
    
    [root@demo ~]# dstat -c -C total -l -p -m -s -g -d -D total -r
    ----total-usage---- ---load-avg--- ---procs--- ------memory-usage----- ----swap--- ---paging-- -dsk/total- --io/total-
    usr sys idl wai stl| 1m   5m  15m |run blk new| used  free  buf   cach| used  free|  in   out | read  writ| read  writ
                       |0.10 0.05 0.09|2.0   0    | 412M 2409M 1372k  868M| 120M  904M|           |           |           
      0   0 100   0   0|0.10 0.05 0.09|1.0   0   0| 412M 2409M 1372k  868M| 120M  904M|   0     0 |   0    40k|   0  3.00 
      0   0 100   0   0|0.10 0.05 0.09|  0   0   0| 412M 2409M 1372k  868M| 120M  904M|   0     0 |   0     0 |   0  1.50 
      0   0  99   0   0|0.10 0.05 0.09|  0   0   0| 412M 2409M 1372k  868M| 120M  904M|   0     0 |   0     0 |   0     0 
      0   0  99   0   0|0.10 0.05 0.09|  0   0   0| 412M 2409M 1372k  868M| 120M  904M|   0     0 |   0     0 |   0     0 
      2   2  98   0   0|0.25 0.08 0.10|  0   0 8.0| 412M 2409M 1372k  868M| 120M  904M|   0     0 |   0     0 |   0     0 
    ...skipping...
    
    [root@demo ~]# sar -BbdqrSuvW 1 1
    Linux 4.18.0-372.19.1.el8_6.x86_64 (demo.example.local) 	19/08/2022 	_x86_64_	(2 CPU)
    
    16:53:37        CPU     %user     %nice   %system   %iowait    %steal     %idle
    16:53:38        all      0,00      0,00      0,50      0,00      0,00     99,50
    
    16:53:37     pswpin/s pswpout/s
    16:53:38         0,00      0,00
    
    16:53:37     pgpgin/s pgpgout/s   fault/s  majflt/s  pgfree/s pgscank/s pgscand/s pgsteal/s    %vmeff
    16:53:38         0,00      0,00      0,00      0,00     35,00      0,00      0,00      0,00      0,00
    
    16:53:37          tps      rtps      wtps   bread/s   bwrtn/s
    16:53:38         0,00      0,00      0,00      0,00      0,00
    
    16:53:37    kbmemfree   kbavail kbmemused  %memused kbbuffers  kbcached  kbcommit   %commit  kbactive   kbinact   kbdirty
    16:53:38      2476012   3150664   1345300     35,21      1372    889064    594740     12,21    663432    448084        44
    
    16:53:37    kbswpfree kbswpused  %swpused  kbswpcad   %swpcad
    16:53:38       926068    122504     11,68     68400     55,83
    
    16:53:37    dentunusd   file-nr  inode-nr    pty-nr
    16:53:38        17942      2784     38368         1
    
    16:53:37      runq-sz  plist-sz   ldavg-1   ldavg-5  ldavg-15   blocked
    16:53:38            1       226      0,03      0,03      0,06         0
    
    16:53:37          DEV       tps     rkB/s     wkB/s   areq-sz    aqu-sz     await     svctm     %util
    16:53:38     dev252-0      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    16:53:38      dev11-0      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    16:53:38     dev253-0      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    16:53:38     dev253-1      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    16:53:38       dev8-0      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    16:53:38      dev8-16      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    16:53:38     dev253-2      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    16:53:38     dev253-3      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    
    Average:        CPU     %user     %nice   %system   %iowait    %steal     %idle
    Average:        all      0,00      0,00      0,50      0,00      0,00     99,50
    
    Average:     pswpin/s pswpout/s
    Average:         0,00      0,00
    
    Average:     pgpgin/s pgpgout/s   fault/s  majflt/s  pgfree/s pgscank/s pgscand/s pgsteal/s    %vmeff
    Average:         0,00      0,00      0,00      0,00     35,00      0,00      0,00      0,00      0,00
    
    Average:          tps      rtps      wtps   bread/s   bwrtn/s
    Average:         0,00      0,00      0,00      0,00      0,00
    
    Average:    kbmemfree   kbavail kbmemused  %memused kbbuffers  kbcached  kbcommit   %commit  kbactive   kbinact   kbdirty
    Average:      2476012   3150664   1345300     35,21      1372    889064    594740     12,21    663432    448084        44
    
    Average:    kbswpfree kbswpused  %swpused  kbswpcad   %swpcad
    Average:       926068    122504     11,68     68400     55,83
    
    Average:    dentunusd   file-nr  inode-nr    pty-nr
    Average:        17942      2784     38368         1
    
    Average:      runq-sz  plist-sz   ldavg-1   ldavg-5  ldavg-15   blocked
    Average:            1       226      0,03      0,03      0,06         0
    
    Average:          DEV       tps     rkB/s     wkB/s   areq-sz    aqu-sz     await     svctm     %util
    Average:     dev252-0      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    Average:      dev11-0      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    Average:     dev253-0      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    Average:     dev253-1      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    Average:       dev8-0      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    Average:      dev8-16      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    Average:     dev253-2      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    Average:     dev253-3      0,00      0,00      0,00      0,00      0,00      0,00      0,00      0,00
    
    [root@demo ~]# cifsiostat 1 3
    Linux 4.18.0-372.19.1.el8_6.x86_64 (demo.example.local) 	19/08/2022 	_x86_64_	(2 CPU)
    
    Filesystem                     rB/s         wB/s    rops/s    wops/s         fo/s         fc/s         fd/s
    
    Filesystem                     rB/s         wB/s    rops/s    wops/s         fo/s         fc/s         fd/s
    
    Filesystem                     rB/s         wB/s    rops/s    wops/s         fo/s         fc/s         fd/s
    
    [root@demo ~]# pidstat
    Linux 4.18.0-372.19.1.el8_6.x86_64 (demo.example.local) 	19/08/2022 	_x86_64_	(2 CPU)
    
    16:55:55      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command
    16:55:55        0         1    0,00    0,01    0,00    0,00    0,01     0  systemd
    16:55:55        0         2    0,00    0,00    0,00    0,00    0,00     0  kthreadd
    16:55:55        0        12    0,00    0,00    0,00    0,01    0,00     0  ksoftirqd/0
    16:55:55        0        13    0,00    0,02    0,00    0,13    0,02     0  rcu_sched
    16:55:55        0        14    0,00    0,00    0,00    0,00    0,00     0  migration/0
    16:55:55        0        15    0,00    0,00    0,00    0,00    0,00     0  watchdog/0
    16:55:55        0        18    0,00    0,00    0,00    0,00    0,00     1  watchdog/1
    16:55:55        0        19    0,00    0,00    0,00    0,00    0,00     1  migration/1
    16:55:55        0        20    0,00    0,00    0,00    0,01    0,00     1  ksoftirqd/1
    16:55:55        0        27    0,00    0,00    0,00    0,00    0,00     0  kauditd
    16:55:55        0        28    0,00    0,00    0,00    0,00    0,00     0  khungtaskd
    16:55:55        0        29    0,00    0,00    0,00    0,00    0,00     1  oom_reaper
    16:55:55        0        31    0,00    0,00    0,00    0,00    0,00     1  kcompactd0
    16:55:55        0        33    0,00    0,01    0,00    0,00    0,01     1  khugepaged
    16:55:55        0        42    0,00    0,00    0,00    0,00    0,00     0  kworker/0:1H-kblockd
    16:55:55        0        76    0,00    0,00    0,00    0,00    0,00     1  kswapd0
    16:55:55        0       192    0,00    0,00    0,00    0,00    0,00     1  irq/30-pciehp
    16:55:55        0       314    0,00    0,00    0,00    0,00    0,00     1  kworker/1:1H-kblockd
    16:55:55        0       492    0,00    0,00    0,00    0,00    0,00     0  scsi_eh_0
    16:55:55        0       629    0,00    0,01    0,00    0,02    0,01     1  xfsaild/dm-0
    16:55:55        0       725    0,00    0,00    0,00    0,00    0,00     0  systemd-journal
    16:55:55        0       765    0,00    0,00    0,00    0,00    0,00     0  systemd-udevd
    16:55:55       32       894    0,00    0,00    0,00    0,00    0,00     1  rpcbind
    16:55:55        0       897    0,00    0,00    0,00    0,00    0,00     0  auditd
    16:55:55        0       899    0,00    0,00    0,00    0,00    0,00     0  sedispatch
    16:55:55        0       939    0,00    0,00    0,00    0,00    0,00     1  sssd
    16:55:55        0       940    0,00    0,00    0,00    0,00    0,00     1  smartd
    16:55:55      998       942    0,00    0,00    0,00    0,00    0,00     1  polkitd
    16:55:55       81       943    0,00    0,00    0,00    0,01    0,00     0  dbus-daemon
    16:55:55        0       947    0,00    0,00    0,00    0,00    0,00     0  systemd-machine
    16:55:55        0       949    0,00    0,00    0,00    0,00    0,00     1  irqbalance
    16:55:55        0       966    0,00    0,00    0,00    0,00    0,00     1  ksmtuned
    16:55:55        0       972    0,00    0,00    0,00    0,00    0,00     1  firewalld
    16:55:55        0       979    0,00    0,00    0,00    0,00    0,00     1  NetworkManager
    16:55:55        0       988    0,00    0,00    0,00    0,00    0,00     0  sshd
    16:55:55        0       989    0,14    0,06    0,00    0,02    0,21     0  tuned
    16:55:55      979       995    0,08    0,08    0,00    0,01    0,15     1  redis-server
    16:55:55        0      1016    0,00    0,00    0,00    0,00    0,00     1  sssd_be
    16:55:55        0      1037    0,00    0,00    0,00    0,00    0,00     0  sssd_nss
    16:55:55        0      1111    0,00    0,00    0,00    0,00    0,00     0  systemd-logind
    16:55:55        0      1243    0,00    0,00    0,00    0,00    0,00     0  rsyslogd
    16:55:55        0      1253    0,00    0,00    0,00    0,00    0,00     1  iscsid
    16:55:55        0      1339    0,00    0,00    0,00    0,00    0,00     1  crond
    16:55:55      980      1532    0,00    0,00    0,00    0,00    0,00     1  pmcd
    16:55:55        0      1547    0,00    0,00    0,00    0,00    0,00     1  pmdaroot
    16:55:55        0      1556    0,00    0,01    0,00    0,00    0,01     1  pmdaproc
    16:55:55        0      1561    0,00    0,00    0,00    0,00    0,00     1  pmdaxfs
    16:55:55        0      1564    0,00    0,00    0,00    0,00    0,01     1  pmdalinux
    16:55:55        0      1575    0,00    0,00    0,00    0,00    0,00     1  pmdakvm
    16:55:55      980      1580    0,02    0,00    0,00    0,00    0,02     0  pmproxy
    16:55:55      980      2019    0,00    0,00    0,00    0,00    0,00     0  pmlogger
    16:55:55        0      2379    0,00    0,00    0,00    0,00    0,00     0  systemd
    16:55:55      985      2987    0,00    0,00    0,00    0,00    0,00     0  cockpit-tls
    16:55:55        0      3029    0,00    0,00    0,00    0,00    0,00     1  dbus-daemon
    16:55:55        0      4592    0,01    0,00    0,00    0,00    0,02     1  rhsm-service
    16:55:55        0     16234    0,00    0,00    0,00    0,00    0,00     1  agetty
    16:55:55        0     66652    0,00    0,00    0,00    0,00    0,00     0  multipathd
    16:55:55        0    117704    0,00    0,00    0,00    0,00    0,00     1  snmpd
    16:55:55        0    118314    0,00    0,00    0,00    0,00    0,00     0  sshd
    16:55:55        0    118317    0,00    0,00    0,00    0,00    0,00     0  sshd
    16:55:55        0    118318    0,00    0,00    0,00    0,00    0,00     0  bash
    16:55:55        0    119672    0,00    0,00    0,00    0,00    0,00     1  kworker/u4:0-events_unbound
    16:55:55        0    119701    0,00    0,00    0,00    0,00    0,00     0  kworker/0:0-cgroup_pidlist_destroy
    16:55:55        0    119749    0,00    0,00    0,00    0,00    0,00     1  kworker/1:0-events_power_efficient
    16:55:55        0    119783    0,00    0,00    0,00    0,00    0,00     0  kworker/0:2-cgroup_pidlist_destroy
    16:55:55        0    119835    0,00    0,00    0,00    0,00    0,00     0  kworker/0:1-cgroup_destroy
    16:55:55        0    120250    0,00    0,00    0,00    0,00    0,00     1  kworker/1:1-events
    16:55:55        0    120347    0,00    0,00    0,00    0,00    0,00     1  pidstat
    
    [root@demo ~]# for i in $(pidof sshd); do pidstat -p $i; done
    Linux 4.18.0-372.19.1.el8_6.x86_64 (demo.example.local) 	19/08/2022 	_x86_64_	(2 CPU)
    
    16:59:34      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command
    16:59:34        0    120378    0,00    0,00    0,00    0,00    0,00     1  sshd
    Linux 4.18.0-372.19.1.el8_6.x86_64 (demo.example.local) 	19/08/2022 	_x86_64_	(2 CPU)
    
    16:59:34      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command
    16:59:34        0    120375    0,00    0,00    0,00    0,00    0,00     0  sshd
    Linux 4.18.0-372.19.1.el8_6.x86_64 (demo.example.local) 	19/08/2022 	_x86_64_	(2 CPU)
    
    16:59:34      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command
    16:59:34        0    118317    0,00    0,00    0,00    0,00    0,00     1  sshd
    Linux 4.18.0-372.19.1.el8_6.x86_64 (demo.example.local) 	19/08/2022 	_x86_64_	(2 CPU)
    
    16:59:34      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command
    16:59:34        0    118314    0,00    0,00    0,00    0,00    0,00     0  sshd
    Linux 4.18.0-372.19.1.el8_6.x86_64 (demo.example.local) 	19/08/2022 	_x86_64_	(2 CPU)
    
    16:59:34      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command
    16:59:34        0       988    0,00    0,00    0,00    0,00    0,00     0  sshd
    
    [root@demo ~]# ps aux
    USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
    root           1  0.0  0.3 243712 13636 ?        Ss   ago17   0:21 /usr/lib/systemd/systemd --switched-root --system --deserialize 18
    root           2  0.0  0.0      0     0 ?        S    ago17   0:00 [kthreadd]
    root           3  0.0  0.0      0     0 ?        I<   ago17   0:00 [rcu_gp]
    root           4  0.0  0.0      0     0 ?        I<   ago17   0:00 [rcu_par_gp]
    root           6  0.0  0.0      0     0 ?        I<   ago17   0:00 [kworker/0:0H-events_highpri]
    root           9  0.0  0.0      0     0 ?        I<   ago17   0:00 [mm_percpu_wq]
    ...skipping...
    
    [root@demo ~]# /usr/share/bcc/tools/biolatency 
    Tracing block device I/O... Hit Ctrl-C to end.
    ^C
         usecs               : count     distribution
             0 -> 1          : 0        |                                        |
             2 -> 3          : 0        |                                        |
             4 -> 7          : 0        |                                        |
             8 -> 15         : 0        |                                        |
            16 -> 31         : 0        |                                        |
            32 -> 63         : 0        |                                        |
            64 -> 127        : 3        |**********                              |
           128 -> 255        : 12       |****************************************|
           256 -> 511        : 3        |**********                              |
           512 -> 1023       : 4        |*************                           |
          1024 -> 2047       : 7        |***********************                 |
          2048 -> 4095       : 0        |                                        |
          4096 -> 8191       : 0        |                                        |
          8192 -> 16383      : 0        |                                        |
         16384 -> 32767      : 0        |                                        |
         32768 -> 65535      : 0        |                                        |
         65536 -> 131071     : 0        |                                        |
        131072 -> 262143     : 0        |                                        |
        262144 -> 524287     : 1        |***                                     |
    
    [root@demo ~]# /usr/share/bcc/tools/cachestat -T
    TIME         HITS   MISSES  DIRTIES HITRATIO   BUFFERS_MB  CACHED_MB
    17:03:48        0        0        0    0.00%            6       1454
    17:03:50        1        0        0  100.00%            6       1454
    17:03:51        0        0        0    0.00%            6       1454
    17:03:52        0        0        0    0.00%            6       1454
    17:03:53        0        0        0    0.00%            6       1454
    17:03:54        0        0        0    0.00%            6       1454
    17:03:55        0        0        0    0.00%            6       1454
    17:03:56        0        0        0    0.00%            6       1454
    17:03:57        0        0        0    0.00%            6       1454
    17:03:58        0        0        0    0.00%            6       1454
    17:03:59        0        0        0    0.00%            6       1454
    17:04:00        0        0        0    0.00%            6       1454
    17:04:01        0        0        0    0.00%            6       1454
    17:04:02        0        0        0    0.00%            6       1454
    17:04:03        0        0        0    0.00%            6       1454
    ^C17:04:04        0        0        0    0.00%            6       1454
    Detaching...
