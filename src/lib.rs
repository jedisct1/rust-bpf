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
