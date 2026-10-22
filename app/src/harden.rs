//! What the process does to keep the secrets it holds from leaving it: no core dump to write
//! them to disk, none of the user's other processes reading its memory, and its memory kept out
//! of swap as far as the system allows. Secrets are also wiped as they are dropped (`zeroize`);
//! this covers the ways they leave before then.

/// How much of the process's memory is kept out of swap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Locked {
    /// All of it, as it is mapped: the limit on locked memory allows it.
    All,
    /// The app's own state, where the open wallet's seed, words and key live, but not the rest:
    /// the limit allows this many bytes.
    App { limit: u64 },
    /// None: this system has no way to lock it.
    #[cfg(not(target_os = "linux"))]
    None,
}

/// Turns off core dumps, closes the process to other processes of the user's, and locks all its
/// memory when the limit on locked memory allows: unlimited, as the handhelds' service sets it.
pub fn harden() -> Locked {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: plain system calls with arguments of the types they take.
        unsafe {
            // Not dumpable: no core file, and /proc/<pid>/mem and ptrace closed to the user's
            // other processes, as for a setuid program.
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            // No core file either should the above be undone, and none for a child.
            let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            libc::setrlimit(libc::RLIMIT_CORE, &none);
            let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit);
            // Locking what is mapped later fails mappings past the limit, so only with none.
            if limit.rlim_cur == libc::RLIM_INFINITY {
                let flags = libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT;
                if libc::mlockall(flags) == 0 {
                    return Locked::All;
                }
            }
            Locked::App { limit: limit.rlim_cur }
        }
    }
    #[cfg(not(target_os = "linux"))]
    Locked::None
}

/// Locks the pages `value` is on into memory, out of swap, and returns whether it could. For the
/// app's state when the rest cannot be locked: its pages stay locked for as long as the process
/// runs, which is as long as the app does.
pub fn lock<T>(value: &T) -> bool {
    #[cfg(unix)]
    {
        let size = std::mem::size_of_val(value);
        // SAFETY: mlock reads nothing; it takes any address range, rounding it out to pages.
        unsafe { libc::mlock((value as *const T).cast(), size) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = value;
        false
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn a_hardened_process_dumps_nothing_and_locks_what_it_can() {
        let locked = harden();
        // SAFETY: as above.
        let (dumpable, core) = unsafe {
            let mut core = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
            libc::getrlimit(libc::RLIMIT_CORE, &mut core);
            (libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0), core.rlim_max)
        };
        assert_eq!((dumpable, core), (0, 0));
        assert!(matches!(locked, Locked::All | Locked::App { .. }));
        // A page or two fits under any limit a system sets.
        let secret = Box::new([7u8; 64]);
        assert!(lock(&*secret));
    }
}
