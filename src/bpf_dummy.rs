use std::io::Error;
use std::os::unix::io::RawFd;

#[derive(Debug, Clone, Default)]
pub struct Prog;

#[derive(Debug, Clone)]
pub struct Op {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl Op {
    pub fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

#[macro_export]
macro_rules! bpfprog {
    ($count:expr, $($code:tt $jt:tt $jf:tt $k:tt),*) => {
        $crate::Prog::default()
    };
}

#[allow(unused_variables)]
pub fn attach_filter(fd: RawFd, prog: Prog) -> Result<(), Error> {
    Ok(())
}

#[allow(unused_variables)]
pub fn detach_filter(fd: RawFd) -> Result<(), Error> {
    Ok(())
}

#[allow(unused_variables)]
pub fn lock_filter(fd: RawFd) -> Result<(), Error> {
    Ok(())
}
