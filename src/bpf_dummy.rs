use std::io::Error;
use std::os::unix::io::RawFd;

#[derive(Debug)]
pub struct Prog;

#[macro_export]
macro_rules! bpfprog {
    ($count:expr, $($code:tt $jt:tt $jf:tt $k:tt),*) => { Prog }
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
