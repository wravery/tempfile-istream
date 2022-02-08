use windows::{
    core::Result,
    Win32::{
        Foundation::{MAX_PATH, PWSTR},
        Storage::FileSystem::{
            GetTempFileNameW, GetTempPathW, FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_DELETE_ON_CLOSE,
        },
        System::Com::{
            IStream,
            StructuredStorage::{STGM_CREATE, STGM_READWRITE, STGM_SHARE_EXCLUSIVE},
            STREAM_SEEK_SET,
        },
        UI::Shell::SHCreateStreamOnFileEx,
    },
};

pub fn new_stream(prefix: &str) -> Result<IStream> {
    const PATH_LEN: usize = (MAX_PATH + 1) as usize;
    let mut dir = [0_u16; PATH_LEN];
    let mut file = [0_u16; PATH_LEN];
    Ok(unsafe {
        GetTempPathW(dir.len() as u32, PWSTR(dir.as_mut_ptr()));
        GetTempFileNameW(PWSTR(dir.as_mut_ptr()), prefix, 0, PWSTR(file.as_mut_ptr()));
        SHCreateStreamOnFileEx(
            PWSTR(file.as_mut_ptr()),
            STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
            true,
            None,
        )?
    })
}

pub fn new_stream_with_bytes(prefix: &str, content: &[u8]) -> Result<IStream> {
    let stream = new_stream(prefix)?;
    unsafe {
        stream.Write(std::mem::transmute(content.as_ptr()), content.len() as u32)?;
        stream.Seek(0, STREAM_SEEK_SET)?;
    }
    Ok(stream)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;
    use windows::Win32::System::Com::{IStream, STREAM_SEEK_SET};

    const TEST_PREFIX: &'static str = "tfi";

    #[test]
    fn new_tempfile_stream() {
        new_stream(TEST_PREFIX).expect("create tempfile");
    }

    #[test]
    fn with_bytes_and_read() {
        let text = b"with_bytes_and_read";
        let stream: IStream = new_stream_with_bytes(TEST_PREFIX, text)
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
        let stream: IStream = new_stream(TEST_PREFIX).expect("create tempfile").into();
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
