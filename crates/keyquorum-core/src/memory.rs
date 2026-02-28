use std::io;

/// Disable core dumps and /proc/self/mem access for this process.
/// Must be called early in main() before any secrets are loaded.
/// On non-Linux platforms, this is a no-op.
pub fn disable_core_dumps() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        let ret = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Prevent exec'd child processes from gaining new privileges.
/// Blocks setuid/setgid, Linux Security Module transitions, etc.
/// On non-Linux platforms, this is a no-op.
pub fn set_no_new_privs() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Lock a memory region so it is never swapped to disk.
pub fn mlock_slice(data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    unsafe {
        let ret = libc::mlock(data.as_ptr() as *const libc::c_void, data.len());
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Unlock a previously mlocked region.
pub fn munlock_slice(data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    unsafe {
        let ret = libc::munlock(data.as_ptr() as *const libc::c_void, data.len());
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Mark memory pages as DONTFORK to prevent copy-on-write leaks to child processes.
/// On non-Linux platforms (where MADV_DONTFORK is unavailable), this is a no-op.
pub fn madvise_dontfork(data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let (aligned_ptr, aligned_len) = page_align_region(data.as_ptr(), data.len());
        unsafe {
            let ret = libc::madvise(aligned_ptr, aligned_len, libc::MADV_DONTFORK);
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Mark memory pages as DONTDUMP to exclude them from core dumps.
/// Complements PR_SET_DUMPABLE — if dumpable is re-enabled later (e.g. by
/// a signal handler), these pages are still excluded.
/// On non-Linux platforms (where MADV_DONTDUMP is unavailable), this is a no-op.
pub fn madvise_dontdump(data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let (aligned_ptr, aligned_len) = page_align_region(data.as_ptr(), data.len());
        unsafe {
            let ret = libc::madvise(aligned_ptr, aligned_len, libc::MADV_DONTDUMP);
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Apply all memory protections to a buffer containing secret material.
/// Returns a list of any protections that failed (empty = all succeeded).
pub fn protect_secret(data: &[u8]) -> Vec<(&'static str, io::Error)> {
    let mut failures = Vec::new();
    if let Err(e) = mlock_slice(data) {
        failures.push(("mlock", e));
    }
    if let Err(e) = madvise_dontfork(data) {
        failures.push(("madvise(DONTFORK)", e));
    }
    if let Err(e) = madvise_dontdump(data) {
        failures.push(("madvise(DONTDUMP)", e));
    }
    failures
}

/// Call all hardening functions at process startup.
pub fn harden_process() -> io::Result<()> {
    disable_core_dumps()?;
    set_no_new_privs()?;
    Ok(())
}

/// Print a warning on non-Linux platforms where security features are degraded.
pub fn warn_if_not_linux() {
    #[cfg(not(target_os = "linux"))]
    eprintln!(
        "WARNING: macOS/non-Linux platform detected. Memory hardening (DONTFORK, \
         DONTDUMP, prctl) is unavailable. This best-effort build is experimental \
         and untested by the project maintainers, and may not be suitable for production."
    );
}

fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

fn page_align_region(ptr: *const u8, len: usize) -> (*mut libc::c_void, usize) {
    let ps = page_size();
    let addr = ptr as usize;
    let aligned_addr = addr & !(ps - 1);
    let aligned_len = (addr + len - aligned_addr + ps - 1) & !(ps - 1);
    (aligned_addr as *mut libc::c_void, aligned_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_process_succeeds() {
        // Should succeed (we're running as root in test environment)
        harden_process().unwrap();
    }

    #[test]
    fn mlock_and_munlock_small_buffer() {
        let buf = vec![0u8; 64];
        // mlock may fail if RLIMIT_MEMLOCK is too low, so just check it doesn't panic
        if mlock_slice(&buf).is_ok() {
            munlock_slice(&buf).unwrap();
        }
    }

    #[test]
    fn mlock_empty_buffer_is_noop() {
        let buf: Vec<u8> = vec![];
        mlock_slice(&buf).unwrap();
        munlock_slice(&buf).unwrap();
    }

    #[test]
    fn page_align_region_works() {
        let ps = page_size();
        let buf = [0u8; 100];
        let (aligned_ptr, aligned_len) = page_align_region(buf.as_ptr(), buf.len());
        let aligned_addr = aligned_ptr as usize;
        assert_eq!(aligned_addr % ps, 0, "address should be page-aligned");
        assert_eq!(aligned_len % ps, 0, "length should be page-aligned");
        assert!(
            aligned_len >= buf.len(),
            "aligned length should cover the buffer"
        );
    }

    #[test]
    fn protect_secret_on_small_buffer() {
        let buf = vec![0u8; 64];
        let failures = protect_secret(&buf);
        // May fail on RLIMIT_MEMLOCK, but should not panic
        for (name, err) in &failures {
            eprintln!("protect_secret: {} failed: {} (non-fatal in test)", name, err);
        }
    }

    #[test]
    fn set_no_new_privs_succeeds() {
        set_no_new_privs().unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn madvise_dontdump_works() {
        let buf = vec![0u8; 64];
        // Should succeed on Linux
        madvise_dontdump(&buf).unwrap();
    }
}
