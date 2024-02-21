from bcc import BPF
import os
from ctypes import c_uint64

def get_path(name):
    relative_path = os.path.join(os.path.dirname(__file__), name)
    absolute_path = os.path.abspath(relative_path)  
    return absolute_path

monitor_pid = os.getpid()

# Define eBPF program
prog = f"""
#define MONITOR_PID {monitor_pid}
#include <linux/sched.h>
#include <linux/ptrace.h>

struct data_t {{
    u32 pid;
    u32 syscall;
    char comm[TASK_COMM_LEN];
}};

BPF_PERF_OUTPUT(syscall_events);

static int submit_syscall_event(struct pt_regs *ctx, u32 syscall_id) {{
    struct data_t data = {{}};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    if (data.pid == MONITOR_PID){{
        return 0;
    }}

    data.syscall = syscall_id;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    syscall_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}}

int get_info_fstat(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 5);
    }}

int get_info_lstat(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 6);
    }}

int get_info_sendfile(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 40);
    }}

int get_info_socket(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 41);
    }}

int get_info_stat(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 4);
    }}

int get_info_umount2(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 166);
    }}

int get_info_uname(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 63);
    }}

int get_info_lseek(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 8);
    }}

int get_info_select(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 23);
    }}

int get_info_access(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 21);
    }}

int get_info_adjtimex(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 159);
    }}

int get_info_alarm(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 37);
    }}

int get_info_brk(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 12);
    }}

int get_info_capget(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 125);
    }}

int get_info_capset(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 126);
    }}

int get_info_chdir(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 80);
    }}

int get_info_chmod(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 90);
    }}

int get_info_chown(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 92);
    }}

int get_info_chroot(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 161);
    }}

int get_info_clock_getres(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 229);
    }}

int get_info_clock_gettime(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 228);
    }}

int get_info_clock_settime(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 227);
    }}

int get_info_clone(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 56);
    }}

int get_info_close(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 3);
    }}

int get_info_creat(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 85);
    }}

int get_info_dup(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 32);
    }}

int get_info_dup2(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 33);
    }}

int get_info_epoll_create(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 213);
    }}

int get_info_epoll_ctl(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 233);
    }}

int get_info_epoll_wait(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 232);
    }}

int get_info_eventfd2(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 290);
    }}

int get_info_execve(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 59);
    }}

int get_info_exit(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 60);
    }}

int get_info_exit_group(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 231);
    }}

int get_info_faccessat(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 269);
    }}

int get_info_fadvise64(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 221);
    }}

int get_info_fallocate(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 285);
    }}

int get_info_fchdir(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 81);
    }}

int get_info_fchmod(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 91);
    }}

int get_info_fchmodat(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 268);
    }}

int get_info_fchown(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 93);
    }}

int get_info_fchownat(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 260);
    }}

int get_info_fcntl(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 72);
    }}

int get_info_fdatasync(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 75);
    }}

int get_info_fgetxattr(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 193);
    }}

int get_info_flistxattr(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 196);
    }}

int get_info_flock(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 73);
    }}

int get_info_fsetxattr(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 190);
    }}

int get_info_newfstatat(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 262);
    }}

int get_info_fstatfs(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 138);
    }}

int get_info_fsync(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 74);
    }}

int get_info_ftruncate(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 77);
    }}

int get_info_futex(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 202);
    }}

int get_info_getcwd(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 79);
    }}

int get_info_getdents(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 78);
    }}

int get_info_getdents64(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 217);
    }}

int get_info_getegid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 108);
    }}

int get_info_geteuid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 107);
    }}

int get_info_getgid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 104);
    }}

int get_info_getgroups(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 115);
    }}

int get_info_getpgid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 121);
    }}

int get_info_getpgrp(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 111);
    }}

int get_info_getpid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 39);
    }}

int get_info_getppid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 110);
    }}

int get_info_getpriority(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 140);
    }}

int get_info_getresgid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 120);
    }}

int get_info_getresuid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 118);
    }}

int get_info_getrusage(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 98);
    }}

int get_info_gettid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 186);
    }}

int get_info_gettimeofday(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 96);
    }}

int get_info_getuid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 102);
    }}

int get_info_getxattr(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 191);
    }}

int get_info_init_module(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 175);
    }}

int get_info_inotify_add_watch(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 254);
    }}

int get_info_inotify_init1(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 294);
    }}

int get_info_inotify_rm_watch(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 255);
    }}

int get_info_ioctl(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 16);
    }}

int get_info_iopl(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 172);
    }}

int get_info_ioprio_set(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 251);
    }}

int get_info_kill(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 62);
    }}

int get_info_lchown(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 94);
    }}

int get_info_lgetxattr(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 192);
    }}

int get_info_link(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 86);
    }}

int get_info_llistxattr(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 195);
    }}

int get_info_madvise(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 28);
    }}

int get_info_mkdir(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 83);
    }}

int get_info_mkdirat(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 258);
    }}

int get_info_mlock(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 149);
    }}

int get_info_mmap(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 9);
    }}

int get_info_mount(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 165);
    }}

int get_info_mprotect(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 10);
    }}

int get_info_mremap(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 25);
    }}

int get_info_msync(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 26);
    }}

int get_info_munlock(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 150);
    }}

int get_info_munmap(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 11);
    }}

int get_info_nanosleep(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 35);
    }}

int get_info_open(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 2);
    }}

int get_info_openat(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 257);
    }}

int get_info_personality(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 135);
    }}

int get_info_pipe(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 22);
    }}

int get_info_pipe2(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 293);
    }}

int get_info_poll(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 7);
    }}

int get_info_ppoll(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 271);
    }}

int get_info_prctl(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 157);
    }}

int get_info_pread64(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 17);
    }}

int get_info_prlimit64(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 302);
    }}

int get_info_pselect6(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 270);
    }}

int get_info_ptrace(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 101);
    }}

int get_info_pwrite64(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 18);
    }}

int get_info_read(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 0);
    }}

int get_info_readlink(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 89);
    }}

int get_info_rename(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 82);
    }}

int get_info_rmdir(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 84);
    }}

int get_info_rt_sigaction(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 13);
    }}

int get_info_rt_sigpending(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 127);
    }}

int get_info_rt_sigprocmask(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 14);
    }}

int get_info_rt_sigreturn(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 15);
    }}

int get_info_rt_sigsuspend(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 130);
    }}

int get_info_rt_sigtimedwait(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 128);
    }}

int get_info_sched_get_priority_max(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 146);
    }}

int get_info_sched_get_priority_min(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 147);
    }}

int get_info_sched_getaffinity(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 204);
    }}

int get_info_sched_getparam(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 143);
    }}

int get_info_sched_getscheduler(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 145);
    }}

int get_info_sched_setparam(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 142);
    }}

int get_info_sched_setscheduler(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 144);
    }}

int get_info_sched_yield(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 24);
    }}

int get_info_set_robust_list(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 273);
    }}

int get_info_set_thread_area(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 205);
    }}

int get_info_set_tid_address(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 218);
    }}

int get_info_setfsgid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 123);
    }}

int get_info_setfsuid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 122);
    }}

int get_info_setgid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 106);
    }}

int get_info_setgroups(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 116);
    }}

int get_info_setitimer(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 38);
    }}

int get_info_setpgid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 109);
    }}

int get_info_setpriority(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 141);
    }}

int get_info_setregid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 114);
    }}

int get_info_setresgid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 119);
    }}

int get_info_setresuid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 117);
    }}

int get_info_setreuid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 113);
    }}

int get_info_setrlimit(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 160);
    }}

int get_info_setsid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 112);
    }}

int get_info_settimeofday(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 164);
    }}

int get_info_setuid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 105);
    }}

int get_info_setxattr(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 188);
    }}

int get_info_sigaltstack(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 131);
    }}

int get_info_statfs(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 137);
    }}

int get_info_symlink(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 88);
    }}

int get_info_sync_file_range(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 277);
    }}

int get_info_sysinfo(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 99);
    }}

int get_info_tgkill(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 234);
    }}

int get_info_time(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 201);
    }}

int get_info_timer_create(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 222);
    }}

int get_info_timer_settime(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 223);
    }}

int get_info_timerfd_create(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 283);
    }}

int get_info_times(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 100);
    }}

int get_info_getrlimit(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 97);
    }}

int get_info_umask(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 95);
    }}

int get_info_unlink(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 87);
    }}

int get_info_unlinkat(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 263);
    }}

int get_info_utime(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 132);
    }}

int get_info_utimensat(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 280);
    }}

int get_info_vfork(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 58);
    }}

int get_info_vhangup(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 153);
    }}

int get_info_wait4(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 61);
    }}

int get_info_waitid(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 247);
    }}

int get_info_write(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 1);
    }}

int get_info_writev(struct pt_regs *ctx) {{
    return submit_syscall_event(ctx, 20);
    }}
"""

# Initialize BPF
b = BPF(text=prog)

# Define the output handler
def print_event(cpu, data, size):
    event = b["syscall_events"].event(data)
    if (event.comm.decode() != "sshd"):
        print(f"PID {event.pid}: Command: {event.syscall}")

with open(get_path("../data/final_syscalls.txt"), 'r') as file:
    syscalls = [value for value in file.read().split()]

# Attach the BPF program to the sys_exit tracepoint (for a specific syscall)
count = 0
array = []
for syscall_name in syscalls:
    try:
        b.attach_kprobe(event=b.get_syscall_fnname(syscall_name), fn_name=f"get_info_{syscall_name}")
    except:
        count += 1
        print(f"{count}: {syscall_name}")
        array.append(syscall_name)
        continue
    
file_path = get_path("unable.txt")
with open(file_path, 'w') as file:
    file.write('\n'.join(map(str, array)))

# Open the perf buffer
b["syscall_events"].open_perf_buffer(print_event)

# Poll for events
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break