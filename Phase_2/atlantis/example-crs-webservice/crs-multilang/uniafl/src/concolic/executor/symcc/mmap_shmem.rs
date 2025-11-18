use crate::common::Error;
use libc::{close, ftruncate, mmap, shm_open, shm_unlink};
use std::ffi::CString;
use std::path::Path;

pub struct MmapShm {
    name: String,
    fd: i32,
    ptr: *mut u8,
    size: usize,
}

impl MmapShm {
    pub fn new(name: impl AsRef<Path>, size: usize) -> Result<Self, Error> {
        let name_ = name.as_ref().to_str().unwrap().to_string();
        let fd = unsafe {
            shm_open(
                CString::new(name_.clone()).unwrap().as_ptr(),
                libc::O_RDWR | libc::O_CREAT,
                0o644,
            )
        };
        if fd == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
        let ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            ) as *mut u8
        };
        if ptr == libc::MAP_FAILED as *mut u8 {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe { ftruncate(fd, size as i64) } == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            name: name_,
            fd,
            ptr,
            size,
        })
    }

    pub fn write_all(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() > self.size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "MmapShm::write_all",
            )
            .into());
        }
        let slice = unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) };
        slice[0..data.len()].copy_from_slice(data);
        Ok(())
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for MmapShm {
    fn drop(&mut self) {
        unsafe {
            close(self.fd);
            shm_unlink(CString::new(self.name.clone()).unwrap().as_ptr());
        }
    }
}
