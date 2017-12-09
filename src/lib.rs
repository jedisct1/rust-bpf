#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

extern crate libc;

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
