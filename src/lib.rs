use std::{
    ffi::c_void,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem, ptr,
    sync::{Mutex, MutexGuard},
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use windows::{
    self as Windows,
    core::{Result, GUID, HRESULT},
    Win32::{
        Foundation::{
            E_FAIL, FILETIME, PWSTR, STG_E_ACCESSDENIED, STG_E_INVALIDFLAG, STG_E_INVALIDFUNCTION,
            STG_E_INVALIDPOINTER, STG_E_MEDIUMFULL, SYSTEMTIME,
        },
        System::{
            Com::{
                CoTaskMemAlloc, ISequentialStream_Impl, IStream, IStream_Impl,
                StructuredStorage::{
                    STATFLAG, STATFLAG_DEFAULT, STATFLAG_NONAME, STGC, STGM_READWRITE,
                },
                STATSTG, STGTY_STREAM, STREAM_SEEK, STREAM_SEEK_CUR, STREAM_SEEK_END,
                STREAM_SEEK_SET,
            },
            Time::SystemTimeToFileTime,
        },
    },
};

use windows_implement::implement;

#[implement(Windows::Win32::System::Com::IStream)]
pub struct TempFileStream(Mutex<File>);

#[allow(non_snake_case)]
impl ISequentialStream_Impl for TempFileStream {
    fn Read(&mut self, pv: *mut c_void, cb: u32, pcbread: *mut u32) -> Result<()> {
        Self::check_buffer(pv)?;
        let mut file = self.get_file()?;
        unsafe {
            let buf: *mut [u8] = ptr::slice_from_raw_parts_mut(mem::transmute(pv), cb as usize);
            let cbRead = map_io_err(file.read(&mut *buf))? as u32;
            if !pcbread.is_null() {
                *pcbread = cbRead;
            }
        }
        Ok(())
    }

    fn Write(&mut self, pv: *const c_void, cb: u32) -> Result<u32> {
        Self::check_buffer(pv)?;
        let mut file = self.get_file()?;
        Ok(unsafe {
            let buf: *const [u8] = ptr::slice_from_raw_parts(mem::transmute(pv), cb as usize);
            map_io_err(file.write(&*buf))?
        } as u32)
    }
}

#[allow(non_snake_case)]
impl IStream_Impl for TempFileStream {
    fn Seek(&mut self, dlibmove: i64, dworigin: STREAM_SEEK) -> Result<u64> {
        let mut file = self.get_file()?;
        let pos = match dworigin {
            STREAM_SEEK_SET => Result::Ok(SeekFrom::Start(dlibmove as u64)),
            STREAM_SEEK_CUR => Result::Ok(SeekFrom::Current(dlibmove)),
            STREAM_SEEK_END => Result::Ok(SeekFrom::End(dlibmove)),
            _ => Err(STG_E_INVALIDFUNCTION.into()),
        }?;
        Ok(map_io_err(file.seek(pos))? as u64)
    }

    fn SetSize(&mut self, libnewsize: u64) -> Result<()> {
        let file = self.get_file()?;
        map_io_err(file.set_len(libnewsize))
    }

    fn CopyTo(
        &mut self,
        pstm: &Option<IStream>,
        cb: u64,
        pcbread: *mut u64,
        pcbwritten: *mut u64,
    ) -> Result<()> {
        let dest = pstm
            .as_ref()
            .map_or(Result::Err(STG_E_INVALIDPOINTER.into()), Ok)?;
        let mut file = self.get_file()?;
        let mut remaining = cb as usize;
        let mut buf = Vec::new();
        buf.resize(remaining.min(BUFFER_SIZE), 0_u8);
        let mut progress = (0_usize, 0_usize);

        let result = loop {
            let read_len = map_io_err(file.read(&mut buf))?;
            if read_len == 0 {
                break Result::Ok(());
            }
            progress.0 += read_len;
            let write_len =
                unsafe { dest.Write(mem::transmute(buf.as_ptr()), read_len as u32) }? as usize;
            progress.1 += write_len;
            if write_len < read_len {
                break Err(STG_E_MEDIUMFULL.into());
            }
            remaining -= read_len;
            buf.truncate(remaining);
        };

        if !pcbread.is_null() {
            unsafe { *pcbread = progress.0 as u64 };
        }
        if !pcbwritten.is_null() {
            unsafe { *pcbwritten = progress.1 as u64 };
        }

        result
    }

    fn Commit(&mut self, _grfcommitflags: STGC) -> Result<()> {
        let mut file = self.get_file()?;
        map_io_err(file.flush())
    }

    fn Revert(&mut self) -> Result<()> {
        Ok(())
    }

    fn LockRegion(&mut self, _liboffset: u64, _cb: u64, _dwlocktype: u32) -> Result<()> {
        Err(STG_E_INVALIDFUNCTION.into())
    }

    fn UnlockRegion(&mut self, _liboffset: u64, _cb: u64, _dwlocktype: u32) -> Result<()> {
        Err(STG_E_INVALIDFUNCTION.into())
    }

    fn Stat(&mut self, pstatstg: *mut STATSTG, grfstatflag: u32) -> Result<()> {
        Self::check_buffer(pstatstg)?;
        unsafe {
            (*pstatstg).pwcsName = pwstr_from_str(match STATFLAG(grfstatflag as i32) {
                STATFLAG_DEFAULT => Result::Ok("tempfile"),
                STATFLAG_NONAME => Result::Ok(""),
                _ => Err(STG_E_INVALIDFLAG.into()),
            }?);
            (*pstatstg).r#type = STGTY_STREAM.0 as u32;
            let metadata = map_io_err(self.get_file()?.metadata())?;
            (*pstatstg).cbSize = metadata.len();
            (*pstatstg).mtime = filetime_from_systemtime(map_io_err(metadata.modified())?)?;
            (*pstatstg).ctime = filetime_from_systemtime(map_io_err(metadata.created())?)?;
            (*pstatstg).atime = filetime_from_systemtime(map_io_err(metadata.accessed())?)?;
            (*pstatstg).grfMode = STGM_READWRITE.0;
            (*pstatstg).grfLocksSupported = 0;
            (*pstatstg).clsid = GUID::zeroed();
            (*pstatstg).grfStateBits = 0;
        }
        Ok(())
    }

    fn Clone(&mut self) -> Result<IStream> {
        let mut src_file = self.get_file()?;
        let src_pos = SeekFrom::Start(map_io_err(src_file.stream_position())?);
        let dest = Self::new()?;
        let result = {
            let mut dest_file = dest.get_file()?;
            map_io_err(src_file.seek(SeekFrom::Start(0)))?;
            let mut buf = [0_u8; BUFFER_SIZE];
            loop {
                let read_len = map_io_err(src_file.read(&mut buf))?;
                if read_len == 0 {
                    break Result::Ok(());
                }

                let write_len = map_io_err(dest_file.write(&buf[0..read_len]))?;
                if write_len != read_len {
                    break Err(STG_E_MEDIUMFULL.into());
                }
            }
        };
        map_io_err(src_file.seek(src_pos))?;
        result?;
        Ok(dest.into())
    }
}

impl TempFileStream {
    pub fn new() -> Result<Self> {
        Ok(Self(Mutex::new(map_io_err(tempfile::tempfile())?)))
    }

    pub fn with_bytes(content: &[u8]) -> Result<Self> {
        let mut file = map_io_err(tempfile::tempfile())?;
        map_io_err(file.write(content))?;
        map_io_err(file.seek(SeekFrom::Start(0)))?;
        Ok(Self(Mutex::new(file)))
    }

    fn get_file(&self) -> Result<MutexGuard<File>> {
        self.0.lock().map_err(|_| STG_E_ACCESSDENIED.into())
    }

    fn check_buffer<T>(p: *const T) -> Result<()> {
        if p.is_null() {
            Err(STG_E_INVALIDPOINTER.into())
        } else {
            Ok(())
        }
    }
}

const BUFFER_SIZE: usize = 4096;

fn map_io_err<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|io_err| io_err.raw_os_error().map_or(E_FAIL, HRESULT).into())
}

fn pwstr_from_str(source: &str) -> PWSTR {
    match source {
        "" => PWSTR(ptr::null_mut()),
        value => {
            let encoded: Vec<_> = value.encode_utf16().chain(std::iter::once(0)).collect();

            unsafe {
                let buffer: *mut u16 =
                    mem::transmute(CoTaskMemAlloc(encoded.len() * mem::size_of::<u16>()));
                let result = PWSTR(buffer);
                let buffer = ptr::slice_from_raw_parts_mut(buffer, encoded.len());
                (*buffer).copy_from_slice(&encoded);
                result
            }
        }
    }
}

fn map_time_err<T>(result: core::result::Result<T, SystemTimeError>) -> Result<T> {
    result.map_err(|_| E_FAIL.into())
}

fn filetime_from_systemtime(system_time: SystemTime) -> Result<FILETIME> {
    let sys_unix_epoch = SYSTEMTIME {
        wYear: 1970,
        wMonth: 1,
        wDay: 1,
        ..Default::default()
    };
    let mut file_unix_epoch = Default::default();
    unsafe { SystemTimeToFileTime(&sys_unix_epoch, &mut file_unix_epoch) }.ok()?;
    let file_unix_epoch =
        ((file_unix_epoch.dwHighDateTime as u64) << 32) | (file_unix_epoch.dwLowDateTime as u64);
    let since_unix_epoch = map_time_err(system_time.duration_since(UNIX_EPOCH))?;
    let since_unix_epoch = (since_unix_epoch.as_nanos() / 100) as u64;
    let value = file_unix_epoch + since_unix_epoch;
    Ok(FILETIME {
        dwHighDateTime: ((value & 0xFFFF_FFFF_0000_0000) >> 32) as u32,
        dwLowDateTime: (value & 0xFFFF_FFFF) as u32,
    })
}

#[cfg(test)]
mod tests {
    use crate::TempFileStream;
    use std::mem;
    use windows::Win32::System::Com::{IStream, STREAM_SEEK_SET};

    #[test]
    fn new_tempfile_stream() {
        TempFileStream::new().expect("create tempfile");
    }

    #[test]
    fn with_bytes_and_read() {
        let text = b"with_bytes_and_read";
        let stream: IStream = TempFileStream::with_bytes(text)
            .expect("create tempfile")
            .into();
        let mut buf = Vec::new();
        buf.resize(text.len() + 1, 0_u8);
        let mut read_len = 0;
        unsafe {
            stream.Read(
                mem::transmute(buf.as_mut_ptr()),
                buf.len() as u32,
                &mut read_len,
            )
        }
        .expect("read bytes");
        assert_eq!(read_len as usize, text.len());
        assert_eq!(text, &buf[0..text.len()]);
        assert_eq!(0, buf[text.len()]);
    }

    #[test]
    fn write_and_read() {
        let text = b"write_and_read";
        let stream: IStream = TempFileStream::new().expect("create tempfile").into();
        let write_len = unsafe { stream.Write(mem::transmute(text.as_ptr()), text.len() as u32) }
            .expect("write bytes") as usize;
        assert_eq!(write_len, text.len());
        unsafe { stream.Seek(0, STREAM_SEEK_SET) }.expect("seek to beginning");
        let mut buf = Vec::new();
        buf.resize(write_len + 1, 0_u8);
        let mut read_len = 0;
        unsafe {
            stream.Read(
                mem::transmute(buf.as_mut_ptr()),
                buf.len() as u32,
                &mut read_len,
            )
        }
        .expect("read bytes");
        assert_eq!(read_len as usize, write_len);
        assert_eq!(text, &buf[0..write_len]);
        assert_eq!(0, buf[write_len]);
    }
}
