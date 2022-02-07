# tempfile-istream

This is a read/write implementation of the [windows](https://crates.io/crates/windows) crate's
[Windows::Win32::System::Com::IStream](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/struct.IStream.html)
interface backed by a temp file on disk. The temp file is created with the [tempfile](https://docs.rs/tempfile/3.3.0/tempfile/) crate,
so it will be deleted by the OS as soon as the `std::fs::File` is closed.

It is intended as an alternative to [SHCreateMemStream](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/UI/Shell/fn.SHCreateMemStream.html) or
[CreateStreamOnHGlobal](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/StructuredStorage/fn.CreateStreamOnHGlobal.html), both of
which will hold the entire stream in memory.
