//! Fixed syscall policy (spec §1.4): default EPERM, arch-checked, x32 and
//! unknown future numbers denied. `decide` is the executable reference for
//! the generated cBPF filter emitted by `build_filter` (x86_64 only — the
//! profile's certified architecture).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Eperm,
    /// clone3 returns ENOSYS so libc falls back to clone (which then enforces
    /// the thread-only flag rules).
    Enosys,
}

impl Decision {
    pub fn errno_name(self) -> &'static str {
        match self {
            Decision::Allow => "ALLOW",
            Decision::Eperm => "EPERM",
            Decision::Enosys => "ENOSYS",
        }
    }
}

/// The unconditional x86_64 allowlist, verbatim from spec §1.4.
pub const ALLOWLIST: &[&str] = &[
    "read",
    "write",
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "close",
    "close_range",
    "lseek",
    "fstat",
    "newfstatat",
    "stat",
    "lstat",
    "statx",
    "open",
    "openat",
    "openat2",
    "access",
    "faccessat",
    "faccessat2",
    "readlink",
    "readlinkat",
    "getdents",
    "getdents64",
    "mmap",
    "mprotect",
    "munmap",
    "mremap",
    "madvise",
    "msync",
    "brk",
    "mincore",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "rt_sigpending",
    "rt_sigtimedwait",
    "rt_sigsuspend",
    "sigaltstack",
    "poll",
    "ppoll",
    "select",
    "pselect6",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "epoll_pwait2",
    "pipe",
    "pipe2",
    "eventfd",
    "eventfd2",
    "dup",
    "dup2",
    "dup3",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "ftruncate",
    "truncate",
    "getpid",
    "getppid",
    "gettid",
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getgroups",
    "getcwd",
    "chdir",
    "fchdir",
    "mkdir",
    "mkdirat",
    "rmdir",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "chmod",
    "fchmod",
    "fchmodat",
    "umask",
    "utime",
    "utimes",
    "utimensat",
    "getrandom",
    "uname",
    "sysinfo",
    "clock_gettime",
    "clock_getres",
    "gettimeofday",
    "time",
    "nanosleep",
    "clock_nanosleep",
    "futex",
    "set_tid_address",
    "set_robust_list",
    "get_robust_list",
    "rseq",
    "membarrier",
    "sched_yield",
    "sched_getaffinity",
    "sched_setaffinity",
    "sched_getparam",
    "sched_getscheduler",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "getrlimit",
    "setrlimit",
    "prlimit64",
    "getrusage",
    "times",
    "arch_prctl",
    "restart_syscall",
    "wait4",
    "waitid",
    "kill",
    "tkill",
    "tgkill",
    "setsid",
    "setpgid",
    "getpgid",
    "getsid",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendmsg",
    "recvmsg",
    "sendto",
    "recvfrom",
    "shutdown",
    "getsockname",
    "getpeername",
    "getsockopt",
    "setsockopt",
];

// clone flag bits
pub const CLONE_VM: u64 = 0x100;
pub const CLONE_FS: u64 = 0x200;
pub const CLONE_FILES: u64 = 0x400;
pub const CLONE_SIGHAND: u64 = 0x800;
pub const CLONE_SYSVSEM: u64 = 0x40000;
pub const CLONE_SETTLS: u64 = 0x80000;
pub const CLONE_PARENT_SETTID: u64 = 0x1000000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x2000000;
pub const CLONE_CHILD_SETTID: u64 = 0x10000000;
pub const CLONE_THREAD: u64 = 0x10000;
pub const EXIT_SIGNAL_MASK: u64 = 0xFF;

const CLONE_REQUIRED: u64 = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD;
const CLONE_ALLOWED: u64 = CLONE_REQUIRED
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_SETTID
    | CLONE_CHILD_CLEARTID;

// socket args
pub const AF_INET: u64 = 2;
pub const AF_INET6: u64 = 10;
pub const CLONE_NEWNET: u64 = 0x4000_0000;
pub const SOCK_STREAM: u64 = 1;
pub const SOCK_CLOEXEC: u64 = 0o2000000;
pub const SOCK_NONBLOCK: u64 = 0o0004000;
pub const IPPROTO_TCP: u64 = 6;

/// Evaluate the fixed policy for (name, primary arg words).
pub fn decide(name: &str, args: &[u64]) -> Decision {
    match name {
        "clone3" => Decision::Enosys,
        "fork" | "vfork" | "socketpair" => Decision::Eperm,
        "clone" => {
            let flags = args.first().copied().unwrap_or(0);
            // x86_64 clone order: flags, stack, parent_tid, child_tid, tls.
            if flags & CLONE_REQUIRED != CLONE_REQUIRED {
                return Decision::Eperm;
            }
            if flags & EXIT_SIGNAL_MASK != 0 {
                return Decision::Eperm; // zero exit-signal bits
            }
            if flags & !CLONE_ALLOWED != 0 {
                return Decision::Eperm;
            }
            Decision::Allow
        }
        "socket" => {
            let (dom, ty, proto) = (
                args.first().copied().unwrap_or(u64::MAX),
                args.get(1).copied().unwrap_or(u64::MAX),
                args.get(2).copied().unwrap_or(u64::MAX),
            );
            if dom != AF_INET {
                return Decision::Eperm;
            }
            if ty != SOCK_STREAM
                && ty != (SOCK_STREAM | SOCK_CLOEXEC)
                && ty != (SOCK_STREAM | SOCK_NONBLOCK)
                && ty != (SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK)
            {
                return Decision::Eperm;
            }
            if proto != 0 && proto != IPPROTO_TCP {
                return Decision::Eperm;
            }
            Decision::Allow
        }
        n => {
            if ALLOWLIST.contains(&n) {
                Decision::Allow
            } else {
                Decision::Eperm
            }
        }
    }
}

/// x86_64 syscall numbers for the policy's special-cased and allowed set.
pub fn nr_x86_64(name: &str) -> Option<u32> {
    Some(match name {
        "read" => 0,
        "write" => 1,
        "open" => 2,
        "close" => 3,
        "stat" => 4,
        "fstat" => 5,
        "lstat" => 6,
        "poll" => 7,
        "lseek" => 8,
        "mmap" => 9,
        "mprotect" => 10,
        "munmap" => 11,
        "brk" => 12,
        "rt_sigaction" => 13,
        "rt_sigprocmask" => 14,
        "rt_sigreturn" => 15,
        "readv" => 19,
        "writev" => 20,
        "access" => 21,
        "pipe" => 22,
        "select" => 23,
        "sched_yield" => 24,
        "mremap" => 25,
        "msync" => 26,
        "mincore" => 27,
        "madvise" => 28,
        "dup" => 32,
        "dup2" => 33,
        "nanosleep" => 35,
        "getpid" => 39,
        "socket" => 41,
        "connect" => 42,
        "accept" => 43,
        "sendto" => 44,
        "recvfrom" => 45,
        "sendmsg" => 46,
        "recvmsg" => 47,
        "shutdown" => 48,
        "bind" => 49,
        "listen" => 50,
        "getsockname" => 51,
        "getpeername" => 52,
        "socketpair" => 53,
        "setsockopt" => 54,
        "getsockopt" => 55,
        "clone" => 56,
        "fork" => 57,
        "vfork" => 58,
        "execve" => 59,
        "exit" => 60,
        "wait4" => 61,
        "kill" => 62,
        "uname" => 63,
        "fcntl" => 72,
        "flock" => 73,
        "fsync" => 74,
        "fdatasync" => 75,
        "truncate" => 76,
        "ftruncate" => 77,
        "getdents" => 78,
        "getcwd" => 79,
        "chdir" => 80,
        "fchdir" => 81,
        "rename" => 82,
        "mkdir" => 83,
        "rmdir" => 84,
        "link" => 85,
        "unlink" => 87,
        "symlink" => 88,
        "chmod" => 90,
        "fchmod" => 91,
        "umask" => 95,
        "gettimeofday" => 96,
        "getrlimit" => 97,
        "getrusage" => 98,
        "sysinfo" => 99,
        "times" => 100,
        "getuid" => 102,
        "getgid" => 104,
        "setpgid" => 109,
        "getppid" => 110,
        "getpgrp" | "getpgid" => 111,
        "setsid" => 112,
        "geteuid" => 107,
        "getegid" => 108,
        "setrlimit" => 160,
        "gettid" => 186,
        "time" => 201,
        "futex" => 202,
        "sched_getaffinity" => 204,
        "sched_setaffinity" => 203,
        "set_thread_area" | "set_tid_address" => 218,
        "clock_gettime" => 228,
        "clock_getres" => 229,
        "clock_nanosleep" => 230,
        "exit_group" => 231,
        "epoll_wait" => 232,
        "epoll_ctl" => 233,
        "tgkill" => 234,
        "utimes" => 235,
        "waitid" => 247,
        "openat" => 257,
        "mkdirat" => 258,
        "mknodat" => 259,
        "unlinkat" => 263,
        "renameat" => 264,
        "linkat" => 265,
        "symlinkat" => 266,
        "readlinkat" => 267,
        "fchmodat" => 268,
        "faccessat" => 269,
        "pselect6" => 270,
        "ppoll" => 271,
        "set_robust_list" => 273,
        "get_robust_list" => 274,
        "utimensat" => 280,
        "epoll_pwait" => 281,
        "pipe2" => 293,
        "accept4" => 288,
        "eventfd2" => 290,
        "epoll_create1" => 291,
        "dup3" => 292,
        "prlimit64" => 302,
        "arch_prctl" => 158,
        "getdents64" => 217,
        "restart_syscall" => 219,
        "pwrite64" => 18,
        "pread64" => 17,
        "eventfd" => 284,
        "fallocate" => 285,
        "timerfd_settime" => 286,
        "timerfd_gettime" => 287,
        "epoll_create" => 213,
        "getgroups" => 115,
        "membarrier" => 324,
        "rseq" => 334,
        "statx" => 332,
        "io_uring_setup" => 425,
        "clone3" => 435,
        "close_range" => 436,
        "openat2" => 437,
        "faccessat2" => 439,
        "newfstatat" => 262,
        "getrandom" => 318,
        "memfd_create" => 319,
        "sched_getparam" => 143,
        "sched_getscheduler" => 145,
        "sched_get_priority_max" => 146,
        "sched_get_priority_min" => 147,
        "getsid" => 124,
        "tkill" => 200,
        "sigaltstack" => 131,
        "rt_sigpending" => 127,
        "rt_sigtimedwait" => 128,
        "rt_sigsuspend" => 130,
        "readlink" => 89,
        "renameat2" => 316,
        "epoll_pwait2" => 441,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// cBPF generator for the x86_64 seccomp profile. Produces the real filter
// program loaded via seccomp(SECCOMP_SET_MODE_FILTER) at launch on a
// certified host.
//
// Classic BPF only jumps forward (jt/jf, u8) except JA which takes an
// absolute index. To keep the layout simple and auditable every conditional
// comparison is emitted as `JMP op jt=0 jf=1; JA <abs target>`: on match it
// falls into the absolute jump; on mismatch it skips it. All block exits are
// JA to the shared terminal returns at program end.
// ---------------------------------------------------------------------------

pub mod bpf {
    use super::nr_x86_64;
    use super::{CLONE_SIGHAND, CLONE_THREAD, CLONE_VM};

    pub const LD_W_ABS: u16 = 0x20;
    pub const JMP_JEQ: u16 = 0x15;
    pub const JMP_JSET: u16 = 0x45;
    pub const JMP_JA: u16 = 0x05;
    pub const RET_K: u16 = 0x16;

    pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
    pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    pub const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
    pub const EPERM: u32 = 1;
    pub const ENOSYS: u32 = 38;

    const OFF_NR: u32 = 0;
    const OFF_ARCH: u32 = 4;
    const OFF_ARG0_LO: u32 = 16;
    const OFF_ARG1_LO: u32 = 24;
    const OFF_ARG2_LO: u32 = 32;

    const REQ: u32 = (CLONE_VM | CLONE_SIGHAND | CLONE_THREAD) as u32; // 0x10900
    const ALLOWED: u32 =
        REQ | 0x200 | 0x400 | 0x40000 | 0x80000 | 0x1000000 | 0x10000000 | 0x2000000;
    const EXIT_SIG: u32 = 0xFF;

    #[derive(Clone, Copy, Debug)]
    pub struct Insn {
        pub code: u16,
        pub jt: u8,
        pub jf: u8,
        pub k: u32,
    }

    fn i(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
        Insn { code, jt, jf, k }
    }

    struct Asm {
        ins: Vec<Insn>,
        labels: Vec<u32>,
        fix: Vec<(usize, usize)>, // (insn index of JA, label)
    }
    impl Asm {
        fn new() -> Self {
            Asm {
                ins: Vec::new(),
                labels: Vec::new(),
                fix: Vec::new(),
            }
        }
        fn label(&mut self) -> usize {
            self.labels.push(u32::MAX);
            self.labels.len() - 1
        }
        fn mark(&mut self, l: usize) {
            self.labels[l] = self.ins.len() as u32;
        }
        fn ld(&mut self, off: u32) {
            self.ins.push(i(LD_W_ABS, 0, 0, off));
        }
        fn ret(&mut self, k: u32) {
            self.ins.push(i(RET_K, 0, 0, k));
        }
        fn ja(&mut self, l: usize) {
            self.ins.push(i(JMP_JA, 0, 0, 0));
            self.fix.push((self.ins.len() - 1, l));
        }
        /// `JMP op k`: match -> JA target; miss -> fall through.
        fn cmp(&mut self, code: u16, k: u32, target: usize) {
            self.ins.push(i(code, 0, 1, k));
            self.ja(target);
        }
        /// `JMP op k`: match -> fall through; miss -> JA target.
        fn cmp_else(&mut self, code: u16, k: u32, target: usize) {
            self.ins.push(i(code, 1, 0, k));
            self.ja(target);
        }
        fn finish(mut self) -> Vec<Insn> {
            for (at, l) in self.fix.drain(..) {
                self.ins[at].k = self.labels[l];
            }
            self.ins
        }
    }

    /// The full cBPF program implementing the §1.4 policy on x86_64.
    pub fn build_filter() -> Vec<Insn> {
        let mut a = Asm::new();
        let allow = a.label();
        let eperm = a.label();
        let enosys = a.label();
        let kill = a.label();
        let socket_blk = a.label();
        let clone_blk = a.label();

        // arch check: foreign personality cannot be trusted (KILL).
        a.ld(OFF_ARCH);
        a.cmp_else(JMP_JEQ, AUDIT_ARCH_X86_64, kill);
        a.ld(OFF_NR);
        // x32 ABI bit -> EPERM
        a.cmp(JMP_JSET, X32_SYSCALL_BIT, eperm);

        // special-cased syscalls
        a.cmp(JMP_JEQ, nr_x86_64("clone3").unwrap(), enosys);
        for n in ["fork", "vfork", "socketpair"] {
            a.cmp(JMP_JEQ, nr_x86_64(n).unwrap(), eperm);
        }
        a.cmp(JMP_JEQ, nr_x86_64("socket").unwrap(), socket_blk);
        a.cmp(JMP_JEQ, nr_x86_64("clone").unwrap(), clone_blk);

        // unconditional allowlist (socket/clone/socketpair excluded - special)
        for name in super::ALLOWLIST {
            if matches!(*name, "socket" | "clone" | "socketpair") {
                continue;
            }
            if let Some(nr) = nr_x86_64(name) {
                a.cmp(JMP_JEQ, nr, allow);
            }
        }
        // default deny
        a.ja(eperm);

        // ---- socket block: AF_INET, SOCK_STREAM|CLOEXEC?|NONBLOCK?, proto 0|6
        a.mark(socket_blk);
        a.ld(OFF_ARG0_LO);
        a.cmp_else(JMP_JEQ, super::AF_INET as u32, eperm);
        a.ld(OFF_ARG2_LO);
        let proto_ok = a.label();
        a.cmp(JMP_JEQ, 0, proto_ok);
        a.cmp_else(JMP_JEQ, super::IPPROTO_TCP as u32, eperm);
        a.mark(proto_ok);
        a.ld(OFF_ARG1_LO);
        let base_ok = a.label();
        a.cmp(
            JMP_JSET,
            !(super::SOCK_STREAM | super::SOCK_CLOEXEC | super::SOCK_NONBLOCK) as u32,
            eperm,
        );
        a.mark(base_ok);
        a.cmp_else(JMP_JSET, super::SOCK_STREAM as u32, eperm);
        a.ja(allow);

        // ---- clone block: required bits, no exit signal, no foreign flags
        a.mark(clone_blk);
        a.ld(OFF_ARG0_LO);
        a.cmp(JMP_JSET, EXIT_SIG, eperm);
        a.cmp(JMP_JSET, !ALLOWED, eperm);
        for bit in [CLONE_VM as u32, CLONE_SIGHAND as u32, CLONE_THREAD as u32] {
            a.cmp_else(JMP_JSET, bit, eperm);
        }
        let _ = REQ;
        a.ja(allow);

        a.mark(allow);
        a.ret(SECCOMP_RET_ALLOW);
        a.mark(eperm);
        a.ret(SECCOMP_RET_ERRNO | EPERM);
        a.mark(enosys);
        a.ret(SECCOMP_RET_ERRNO | ENOSYS);
        a.mark(kill);
        a.ret(SECCOMP_RET_KILL_PROCESS);
        a.finish()
    }

    /// Serialize to the kernel's `struct sock_fprog` array format.
    pub fn to_bytes(p: &[Insn]) -> Vec<u8> {
        let mut out = Vec::with_capacity(p.len() * 8);
        for i in p {
            out.extend_from_slice(&i.code.to_le_bytes());
            out.push(i.jt);
            out.push(i.jf);
            out.extend_from_slice(&i.k.to_le_bytes());
        }
        out
    }
}
