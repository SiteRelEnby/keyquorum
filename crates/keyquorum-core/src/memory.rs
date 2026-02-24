use std::io;

/// Disable core dumps and /proc/self/mem access for this process.
/// Must be called early in main() before any secrets are loaded.
pub fn disable_core_dumps() -> io::Result<()> {
    unsafe {
        let ret = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
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
pub fn madvise_dontfork(data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let (aligned_ptr, aligned_len) = page_align_region(data.as_ptr(), data.len());
    unsafe {
        let ret = libc::madvise(aligned_ptr, aligned_len, libc::MADV_DONTFORK);
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Call all hardening functions at process startup.
pub fn harden_process() -> io::Result<()> {
    disable_core_dumps()?;
    Ok(())
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
}
