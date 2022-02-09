use std::{ffi::OsStr, path::Path};

use windows::{
    core::Result,
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, E_FAIL, E_INVALIDARG, E_OUTOFMEMORY, MAX_PATH, PWSTR},
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

/// Builder for a read/write implementation of the [`windows`] crate's [`IStream`] interface
/// backed by a temp file on disk. The temp file is created with [`SHCreateStreamOnFileEx`], using
/// [`FILE_ATTRIBUTE_TEMPORARY`] and [`FILE_FLAG_DELETE_ON_CLOSE`] so it will be deleted by the OS
/// as soon as the last reference to the [`IStream`] is dropped.
///
/// # Example
///
/// ```
/// use tempfile_istream::Builder;
///
/// let stream = Builder::new("prefix")
///     .with_content(b"binary content")
///     .build()
///     .expect("creates the stream");
/// ```
pub struct Builder<'a> {
    prefix: &'a str,
    content: Option<&'a [u8]>,
}

impl<'a> Builder<'a> {
    /// Create a new [`Builder`] for an empty [`IStream`] backed by a temp file on disk with the
    /// specified filename prefix. Only the first 3 characters of the [`prefix`] parameter will
    /// be used in the filename, but the entire string must match a valid [`std::path::Path`]
    /// `file_stem` or the call to `build` will fail.
    ///
    /// # Example
    ///
    /// ```
    /// use windows::Win32::System::Com::STREAM_SEEK_END;
    /// use tempfile_istream::Builder;
    ///
    /// let stream = Builder::new("prefix")
    ///     .build()
    ///     .expect("creates an empty stream");
    ///
    /// let end_pos = unsafe {
    ///     stream.Seek(0, STREAM_SEEK_END)
    /// }
    /// .expect("end position");
    ///
    /// assert_eq!(0, end_pos, "stream should be empty");
    /// ```
    ///
    /// # See also
    ///
    /// Parameter
    /// [requirements](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettempfilenamew#parameters)
    /// for the `prefix` argument.
    pub fn new(prefix: &'a str) -> Self {
        Self {
            prefix,
            content: None,
        }
    }

    /// Initialize the stream with a [`u8`] slice of bytes and leave the [`IStream`] cursor at the
    /// beginning of the stream so that a consumer can immediately begin reading it back.
    ///
    /// # Example
    ///
    /// ```
    /// use std::mem;
    /// use tempfile_istream::Builder;
    ///
    /// const CONTENT: &[u8] = b"binary content";
    /// const CONTENT_LEN: usize = CONTENT.len();
    ///
    /// let stream = Builder::new("prefix")
    ///     .with_content(CONTENT)
    ///     .build()
    ///     .expect("creates a stream with content");
    ///
    /// let mut buf = [0_u8; CONTENT_LEN];
    /// let mut read_len = 0;
    /// unsafe {
    ///     stream.Read(
    ///         mem::transmute(buf.as_mut_ptr()),
    ///         buf.len() as u32,
    ///         &mut read_len,
    ///     )
    /// }
    /// .expect("read bytes");
    ///
    /// assert_eq!(buf, CONTENT, "should match the initial content");
    /// ```
    pub fn with_content(self, content: &'a [u8]) -> Self {
        Self {
            content: Some(content),
            ..self
        }
    }

    /// Create the [`IStream`] backed by a temp file. This will perform parameter validation
    /// on the `prefix` argument and fail with [`E_INVALIDARG`] if it contains anything other
    /// than a valid [`std::path::Path`] `file_stem`. Only the first 3 characters of the `prefix`
    /// will be used.
    ///
    /// # Example
    ///
    /// ```
    /// use windows::Win32::System::Com::{STREAM_SEEK_CUR, STREAM_SEEK_END};
    /// use tempfile_istream::Builder;
    ///
    /// const CONTENT: &[u8] = b"binary content";
    ///
    /// let stream = Builder::new("prefix")
    ///     .with_content(CONTENT)
    ///     .build()
    ///     .expect("creates a non-empty stream");
    ///
    /// let cur_pos = unsafe {
    ///     stream.Seek(0, STREAM_SEEK_CUR)
    /// }
    /// .expect("current position");
    ///
    /// assert_eq!(0, cur_pos, "current position should be at the beginning");
    ///
    /// let end_pos = unsafe {
    ///     stream.Seek(0, STREAM_SEEK_END)
    /// }
    /// .expect("end position");
    ///
    /// assert_eq!(end_pos as usize, CONTENT.len(), "end position should match content length")
    /// ```
    ///
    /// # See also
    ///
    /// Parameter
    /// [requirements](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettempfilenamew#parameters)
    /// for the `prefix` argument.
    pub fn build(self) -> Result<IStream> {
        if !self.prefix.is_empty()
            && Path::new(self.prefix).file_stem() != Some(OsStr::new(self.prefix))
        {
            return Err(E_INVALIDARG.into());
        }

        const FILE_LEN: usize = (MAX_PATH + 1) as usize;
        const DIR_LEN: usize = FILE_LEN - 14;
        let mut dir = [0_u16; DIR_LEN];
        let mut file = [0_u16; FILE_LEN];

        let stream = unsafe {
            match GetTempPathW(dir.len() as u32, PWSTR(dir.as_mut_ptr())) {
                len if len as usize > dir.len() => Result::Err(E_OUTOFMEMORY.into()),
                _ => Ok(()),
            }?;
            match GetTempFileNameW(
                PWSTR(dir.as_mut_ptr()),
                self.prefix,
                0,
                PWSTR(file.as_mut_ptr()),
            ) {
                unique if unique == ERROR_BUFFER_OVERFLOW.0 => Result::Err(E_OUTOFMEMORY.into()),
                0 => Result::Err(E_FAIL.into()),
                _ => Ok(()),
            }?;

            SHCreateStreamOnFileEx(
                PWSTR(file.as_mut_ptr()),
                (STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE).0,
                (FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE).0,
                true,
                None,
            )?
        };

        if let Some(content) = self.content {
            unsafe {
                stream.Write(std::mem::transmute(content.as_ptr()), content.len() as u32)?;
                stream.Seek(0, STREAM_SEEK_SET)?;
            }
        }

        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;
    use windows::Win32::System::Com::{IStream, STREAM_SEEK_SET};

    const TEST_PREFIX: &'static str = "test";

    #[test]
    fn new_tempfile_stream() {
        Builder::new(TEST_PREFIX).build().expect("create tempfile");
    }

    #[test]
    fn with_bytes_and_read() {
        let text = b"with_bytes_and_read";
        let stream: IStream = Builder::new(TEST_PREFIX)
            .with_content(text)
            .build()
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
        let stream: IStream = Builder::new(TEST_PREFIX)
            .build()
            .expect("create tempfile")
            .into();
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
