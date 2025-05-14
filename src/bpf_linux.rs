use libc::{c_int, c_ushort, c_void, setsockopt, socklen_t, SOL_SOCKET};
use std::io::Error;
use std::mem::size_of_val;
use std::os::unix::io::RawFd;
use std::ptr::null;

/// Represents a single BPF instruction (operation).
///
/// This struct directly maps to the Linux kernel's `sock_filter` structure
/// used for BPF programs. Each operation consists of:
/// - a 16-bit code that defines the operation
/// - 8-bit jump targets for true/false conditions
/// - a 32-bit immediate constant value (k)
///
/// The memory layout must match the kernel's expectation, so we use `repr(C)`.
#[repr(C)]
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
    /// # Parameters
    ///
    /// * `code` - The operation code (e.g., `BPF_LD|BPF_H|BPF_ABS`)
    /// * `jt` - Jump target offset for true condition
    /// * `jf` - Jump target offset for false condition
    /// * `k` - Immediate value whose meaning depends on the operation code
    ///
    /// # Examples
    ///
    /// ```
    /// use bpf::Op;
    ///
    /// // Load the 2-byte value at position 12 (protocol field in Ethernet header)
    /// let load_protocol = Op::new(0x28, 0, 0, 12); // ldh [12]
    /// ```
    pub fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

/// Represents a complete BPF program, consisting of a sequence of operations.
///
/// This struct directly maps to the Linux kernel's `sock_fprog` structure.
/// A program is an array of BPF instructions that are executed sequentially
/// by the kernel to filter packets.
///
/// The memory layout must match the kernel's expectation, so we use `repr(C)`.
/// The struct manages the memory of the operations to ensure safety.
#[repr(C)]
#[derive(Debug)]
pub struct Prog {
    /// Length of the filter program
    len: c_ushort,
    /// Pointer to the filter operations
    filter: *mut Op,
    /// Hold the original boxed slice to properly manage memory
    /// This field is excluded from documentation to match the C structure layout
    #[cfg(not(doc))]
    _ops: Option<Box<[Op]>>,
}

impl Prog {
    /// Creates a new BPF program from a vector of operations.
    ///
    /// This function takes ownership of the operations vector and converts it
    /// into a format suitable for the Linux kernel's BPF filter system.
    /// The operations will be executed in sequence when packets arrive on a socket.
    ///
    /// # Parameters
    ///
    /// * `ops` - A vector of BPF operations that make up the program
    ///
    /// # Examples
    ///
    /// ```
    /// use bpf::{Op, Prog};
    ///
    /// // Create a simple program that accepts all packets
    /// let mut ops = Vec::new();
    /// ops.push(Op::new(0x06, 0, 0, 0xFFFFFFFF)); // ret #UINT_MAX (accept)
    /// let prog = Prog::new(ops);
    /// ```
    ///
    /// # Note
    ///
    /// It's generally easier to use the `bpfprog!` macro to create programs.
    pub fn new(ops: Vec<Op>) -> Self {
        let mut ops = ops.into_boxed_slice();
        let len = ops.len();
        let ptr = ops.as_mut_ptr();

        Self {
            len: len as _,
            filter: ptr,
            _ops: Some(ops),
        }
    }
}

// No longer need custom Drop impl as we're using proper Rust ownership

const SO_ATTACH_FILTER: c_int = 26;
const SO_DETACH_FILTER: c_int = 27;
const SO_LOCK_FILTER: c_int = 44;

/// Macro for creating BPF programs with a more concise syntax.
///
/// This macro allows you to create BPF programs by specifying the operations
/// as a sequence of `code jt jf k` tuples, making it easier to translate BPF
/// assembly code into Rust.
///
/// # Parameters
///
/// * `$count` - The number of operations in the program (for capacity pre-allocation)
/// * `$code $jt $jf $k` - Repeated tuples of operation code, jump-true offset,
///   jump-false offset, and k-value for each operation
///
/// # Examples
///
/// ```
/// use bpf::bpfprog;
///
/// // Create a BPF program that accepts only IPv4 TCP packets
/// let filter = bpfprog!(4,
///     0x28 0 0 0x0000000c,  // ldh [12]             ; load ethertype
///     0x15 0 2 0x00000800,  // jeq #0x800, L1, L3   ; if IPv4, goto L1, else L3
///     0x30 0 0 0x00000017,  // ldb [23]             ; load protocol
///     0x15 0 1 0x00000006   // jeq #6, L2, L3       ; if TCP, accept, else drop
/// );
/// ```
#[macro_export]
macro_rules! bpfprog {
    ($count:expr, $($code:tt $jt:tt $jf:tt $k:tt),*) => {
        {
            let mut ops = Vec::with_capacity($count);
            $(ops.push($crate::Op::new($code, $jt, $jf, $k));)*
            $crate::Prog::new(ops)
        }
    }
}

/// Attaches a BPF filter program to a socket.
///
/// Once attached, the BPF program will filter all incoming packets on the
/// socket. Only packets that match the filter criteria will be delivered
/// to the application.
///
/// # Parameters
///
/// * `fd` - Raw file descriptor of the socket
/// * `prog` - The BPF program to attach
///
/// # Returns
///
/// * `Ok(())` if the filter was successfully attached
/// * `Err(Error)` with the system error if attachment failed
///
/// # Examples
///
/// ```
/// use bpf::{bpfprog, attach_filter};
/// use std::net::UdpSocket;
/// use std::os::unix::io::AsRawFd;
///
/// let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
/// let filter = bpfprog!(1, 0x06 0 0 0x00000001); // ret #1 (accept 1 byte)
///
/// // Attach the filter to the socket
/// let result = attach_filter(socket.as_raw_fd(), filter);
/// ```
///
/// # Safety
///
/// This function is safe to call, but internally uses unsafe code to interact
/// with the operating system. The `fd` must refer to a valid socket.
pub fn attach_filter(fd: RawFd, prog: Prog) -> Result<(), Error> {
    let ret = unsafe {
        setsockopt(
            fd as c_int,
            SOL_SOCKET,
            SO_ATTACH_FILTER,
            &prog as *const _ as *const c_void,
            size_of_val(&prog) as socklen_t,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

/// Detaches any BPF filter program from a socket.
///
/// This removes any previously attached filter, allowing all packets to be
/// delivered to the application again.
///
/// # Parameters
///
/// * `fd` - Raw file descriptor of the socket
///
/// # Returns
///
/// * `Ok(())` if the filter was successfully detached
/// * `Err(Error)` with the system error if detachment failed
///
/// # Examples
///
/// ```
/// use bpf::detach_filter;
/// use std::net::UdpSocket;
/// use std::os::unix::io::AsRawFd;
///
/// let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
///
/// // Detach any filter from the socket
/// let result = detach_filter(socket.as_raw_fd());
/// ```
///
/// # Safety
///
/// This function is safe to call, but internally uses unsafe code to interact
/// with the operating system. The `fd` must refer to a valid socket.
pub fn detach_filter(fd: RawFd) -> Result<(), Error> {
    let ret = unsafe { setsockopt(fd as c_int, SOL_SOCKET, SO_DETACH_FILTER, null(), 0) };

    if ret == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

/// Locks the BPF filter on a socket to prevent it from being replaced.
///
/// Once locked, the filter cannot be modified or removed for the lifetime
/// of the socket. This is a security measure to prevent privilege escalation
/// attacks where a program running with lower privileges might try to replace
/// a filter set by a privileged program.
///
/// # Parameters
///
/// * `fd` - Raw file descriptor of the socket
///
/// # Returns
///
/// * `Ok(())` if the filter was successfully locked
/// * `Err(Error)` with the system error if locking failed
///
/// # Examples
///
/// ```
/// use bpf::{bpfprog, attach_filter, lock_filter};
/// use std::net::UdpSocket;
/// use std::os::unix::io::AsRawFd;
///
/// let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
/// let filter = bpfprog!(1, 0x06 0 0 0x00000001); // ret #1 (accept 1 byte)
///
/// // Attach the filter to the socket
/// attach_filter(socket.as_raw_fd(), filter).unwrap();
///
/// // Lock the filter to prevent it from being modified
/// let result = lock_filter(socket.as_raw_fd());
/// ```
///
/// # Safety
///
/// This function is safe to call, but internally uses unsafe code to interact
/// with the operating system. The `fd` must refer to a valid socket.
///
/// # Note
///
/// This operation is irreversible for the lifetime of the socket.
pub fn lock_filter(fd: RawFd) -> Result<(), Error> {
    let one: c_int = 1;
    let ret = unsafe {
        setsockopt(
            fd as c_int,
            SOL_SOCKET,
            SO_LOCK_FILTER,
            &one as *const _ as *const c_void,
            size_of_val(&one) as socklen_t,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}
