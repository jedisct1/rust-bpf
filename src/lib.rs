//! Rust library for attaching BPF filters to sockets.
//!
//! This library provides a simple interface for creating and attaching
//! Berkeley Packet Filter (BPF) programs to sockets on Linux systems.
//! On non-Linux systems, it provides dummy implementations that maintain
//! API compatibility but don't perform any actual filtering.
//!
//! BPF is a technology used in the Linux kernel to filter network packets
//! at the socket level. It allows applications to efficiently filter packets
//! in kernel space before they're delivered to user space, reducing unnecessary
//! data copies and improving performance.
//!
//! # Features
//!
//! - Create and attach BPF filters to sockets
//! - Detach filters when no longer needed
//! - Lock filters to prevent unauthorized modification
//! - Simple macro syntax for defining BPF programs
//! - Cross-platform API (real implementation on Linux, dummy on other platforms)
//!
//! # Basic Usage
//!
//! ```rust
//! use bpf::{bpfprog, BpfFilterAttachable};
//! use std::net::UdpSocket;
//!
//! fn main() -> std::io::Result<()> {
//!     // Create a socket
//!     let socket = UdpSocket::bind("0.0.0.0:0")?;
//!
//!     // Create a BPF program that only accepts UDP packets on port 53 (DNS)
//!     let filter = bpfprog!(2,
//!         0x30 0 0 0x00000011,  // Load byte at position 17 (IP protocol)
//!         0x15 0 1 0x00000011   // If UDP (17), accept, else drop
//!     );
//!
//!     // Attach the filter to the socket using the trait
//!     socket.attach_filter(filter)?;
//!
//!     // Later, detach if needed
//!     socket.detach_filter()?;
//!
//!     Ok(())
//! }
//! ```

use std::os::unix::io::AsRawFd;

#[cfg(target_os = "linux")]
pub use bpf_linux::*;
#[cfg(target_os = "linux")]
#[macro_use]
mod bpf_linux;

#[cfg(not(target_os = "linux"))]
pub use bpf_dummy::*;
#[cfg(not(target_os = "linux"))]
#[macro_use]
mod bpf_dummy;

/// Trait for types that can have BPF filters attached.
///
/// This trait is automatically implemented for any type that implements `AsRawFd`,
/// allowing you to directly call BPF operations on any socket type without having
/// to manually extract the file descriptor.
///
/// # Examples
///
/// ```rust
/// use bpf::{bpfprog, BpfFilterAttachable};
/// use std::net::{TcpListener, UdpSocket};
///
/// // Works with TcpListener
/// let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
/// let tcp_filter = bpfprog!(1, 0x06 0 0 0x00000001); // ret #1
/// tcp.attach_filter(tcp_filter).unwrap();
///
/// // Works with UdpSocket
/// let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
/// let udp_filter = bpfprog!(1, 0x06 0 0 0x00000001); // ret #1
/// udp.attach_filter(udp_filter).unwrap();
/// ```
pub trait BpfFilterAttachable: AsRawFd {
    /// Attaches a BPF filter to this object.
    ///
    /// Once attached, the BPF program will filter all incoming packets,
    /// allowing only those that match the filter criteria.
    ///
    /// # Parameters
    ///
    /// * `prog` - The BPF program to attach
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the filter was successfully attached
    /// * `Err(std::io::Error)` with the system error if attachment failed
    fn attach_filter(&self, prog: Prog) -> std::io::Result<()> {
        attach_filter(self.as_raw_fd(), prog)
    }

    /// Detaches any BPF filter from this object.
    ///
    /// This removes any previously attached filter, allowing all packets
    /// to be delivered again.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the filter was successfully detached
    /// * `Err(std::io::Error)` with the system error if detachment failed
    fn detach_filter(&self) -> std::io::Result<()> {
        detach_filter(self.as_raw_fd())
    }

    /// Locks the BPF filter to prevent further modifications.
    ///
    /// Once locked, the filter cannot be removed or modified for the lifetime
    /// of the socket. This is a security measure to prevent privilege escalation.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the filter was successfully locked
    /// * `Err(std::io::Error)` with the system error if locking failed
    ///
    /// # Note
    ///
    /// This operation is irreversible for the lifetime of the socket.
    fn lock_filter(&self) -> std::io::Result<()> {
        lock_filter(self.as_raw_fd())
    }
}

// Implement the trait for any type that implements AsRawFd
impl<T: AsRawFd> BpfFilterAttachable for T {}
