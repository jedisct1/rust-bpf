//! Rust library for attaching BPF filters to sockets.
//!
//! This library provides a simple interface for creating and attaching
//! Berkeley Packet Filter (BPF) programs to sockets on Linux systems.
//! On non-Linux systems, it provides dummy implementations.

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
pub trait BpfFilterAttachable: AsRawFd {
    /// Attach a BPF filter to this object.
    fn attach_filter(&self, prog: Prog) -> std::io::Result<()> {
        attach_filter(self.as_raw_fd(), prog)
    }

    /// Detach any BPF filter from this object.
    fn detach_filter(&self) -> std::io::Result<()> {
        detach_filter(self.as_raw_fd())
    }

    /// Lock the BPF filter to prevent further modifications.
    fn lock_filter(&self) -> std::io::Result<()> {
        lock_filter(self.as_raw_fd())
    }
}

// Implement the trait for any type that implements AsRawFd
impl<T: AsRawFd> BpfFilterAttachable for T {}
