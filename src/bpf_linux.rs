use libc::{c_int, c_ushort, c_void, setsockopt, socklen_t, SOL_SOCKET};
use std::io::Error;
use std::mem::size_of_val;
use std::os::unix::io::RawFd;
use std::ptr::null;

#[repr(C)]
#[derive(Debug)]
pub struct Op {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl Op {
    pub fn new(code: u16, jt: u8, jf: u8, k: u32) -> Op {
        Op {
            code: code,
            jt: jt,
            jf: jf,
            k: k,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Prog {
    len: c_ushort,
    filter: *const Op,
}

impl Prog {
    pub fn new(ops: Vec<Op>) -> Prog {
        Prog {
            len: ops.len() as _,
            filter: ops.as_ptr(),
        }
    }
}

const SO_ATTACH_FILTER: c_int = 26;
const SO_DETACH_FILTER: c_int = 27;
const SO_LOCK_FILTER: c_int = 44;

#[macro_export]
macro_rules! bpfprog {
    ($count:expr, $($code:tt $jt:tt $jf:tt $k:tt),*) => {
        {
            let mut ops = Vec::with_capacity($count);
            $(ops.push(bpf::Op::new($code, $jt, $jf, $k));)*
            bpf::Prog::new(ops)
        }
    }
}

pub fn attach_filter(fd: RawFd, prog: Prog) -> Result<(), Error> {
    match unsafe {
        setsockopt(
            fd as c_int,
            SOL_SOCKET,
            SO_ATTACH_FILTER,
            &prog as *const _ as *const c_void,
            size_of_val(&prog) as socklen_t,
        )
    } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

pub fn detach_filter(fd: RawFd) -> Result<(), Error> {
    match unsafe { setsockopt(fd as c_int, SOL_SOCKET, SO_DETACH_FILTER, null(), 0) } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

pub fn lock_filter(fd: RawFd) -> Result<(), Error> {
    let one: c_int = 1;
    match unsafe {
        setsockopt(
            fd as c_int,
            SOL_SOCKET,
            SO_LOCK_FILTER,
            &one as *const _ as *const c_void,
            size_of_val(&one) as socklen_t,
        )
    } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}
