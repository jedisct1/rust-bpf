use std::io::Error;
use std::os::unix::io::RawFd;

/// A dummy implementation of BPF program for non-Linux systems.
///
/// On systems that don't support BPF filters, this provides API compatibility
/// without any actual filtering functionality.
#[derive(Debug, Clone, Default)]
pub struct Prog;

/// A dummy implementation of BPF operation for non-Linux systems.
///
/// This struct mirrors the Linux implementation but doesn't provide any
/// actual filtering functionality on non-Linux systems.
#[derive(Debug, Clone)]
pub struct Op {
    /// The operation code (what action to perform)
    pub code: u16,
    /// Jump target offset if the condition is true
    pub jt: u8,
    /// Jump target offset if the condition is false
    pub jf: u8,
    /// Generic field used for various purposes depending on the operation
    pub k: u32,
}

impl Op {
    /// Creates a new BPF operation with the specified parameters.
    ///
    /// On non-Linux systems, this creates a dummy operation that doesn't
    /// perform any actual filtering.
    ///
    /// # Parameters
    ///
    /// * `code` - The operation code (ignored on non-Linux systems)
    /// * `jt` - Jump target offset for true condition (ignored)
    /// * `jf` - Jump target offset for false condition (ignored)
    /// * `k` - Immediate value (ignored)
    pub fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

/// Macro for creating dummy BPF programs on non-Linux systems.
///
/// This macro provides API compatibility with the Linux version, but creates
/// a dummy program that doesn't perform any actual filtering on non-Linux systems.
///
/// # Parameters
///
/// * `$count` - The number of operations in the program (ignored)
/// * `$code $jt $jf $k` - Repeated tuples of operation parameters (ignored)
#[macro_export]
macro_rules! bpfprog {
    ($count:expr, $($code:tt $jt:tt $jf:tt $k:tt),*) => {
        $crate::Prog::default()
    };
}

/// Attaches a BPF filter program to a socket (dummy implementation).
///
/// On non-Linux systems, this function does nothing and always returns success.
/// It provides API compatibility with the Linux version.
///
/// # Parameters
///
/// * `fd` - Raw file descriptor of the socket (ignored)
/// * `prog` - The BPF program to attach (ignored)
///
/// # Returns
///
/// Always returns `Ok(())` on non-Linux systems.
#[allow(unused_variables)]
pub fn attach_filter(fd: RawFd, prog: Prog) -> Result<(), Error> {
    Ok(())
}

/// Detaches any BPF filter program from a socket (dummy implementation).
///
/// On non-Linux systems, this function does nothing and always returns success.
/// It provides API compatibility with the Linux version.
///
/// # Parameters
///
/// * `fd` - Raw file descriptor of the socket (ignored)
///
/// # Returns
///
/// Always returns `Ok(())` on non-Linux systems.
#[allow(unused_variables)]
pub fn detach_filter(fd: RawFd) -> Result<(), Error> {
    Ok(())
}

/// Locks the BPF filter on a socket (dummy implementation).
///
/// On non-Linux systems, this function does nothing and always returns success.
/// It provides API compatibility with the Linux version.
///
/// # Parameters
///
/// * `fd` - Raw file descriptor of the socket (ignored)
///
/// # Returns
///
/// Always returns `Ok(())` on non-Linux systems.
#[allow(unused_variables)]
pub fn lock_filter(fd: RawFd) -> Result<(), Error> {
    Ok(())
}
