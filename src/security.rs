use libc::{prctl, rlimit, setrlimit, PR_SET_DUMPABLE, RLIMIT_CORE};

pub fn harden_process() {
    disable_core_dumps();
    disallow_ptrace_dump();
}

fn disable_core_dumps() {
    unsafe {
        let limit = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let _ = setrlimit(RLIMIT_CORE, &limit);
    }
}

fn disallow_ptrace_dump() {
    unsafe {
        let _ = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}
