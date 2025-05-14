use libc::{c_int, c_ushort, c_void, setsockopt, socklen_t, SOL_SOCKET};
use std::io::Error;
use std::mem::size_of_val;
use std::os::unix::io::RawFd;
use std::ptr::null;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Op {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl Op {
    pub fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Prog {
    len: c_ushort,
    filter: *mut Op,
    // Hold the original boxed slice to properly manage memory
    #[cfg(not(doc))]
    _ops: Option<Box<[Op]>>,
}

impl Prog {
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

pub fn detach_filter(fd: RawFd) -> Result<(), Error> {
    let ret = unsafe { setsockopt(fd as c_int, SOL_SOCKET, SO_DETACH_FILTER, null(), 0) };

    if ret == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

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
