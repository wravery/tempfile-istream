# tempfile-istream

This is a read/write implementation of the [windows](https://crates.io/crates/windows) crate's
[Windows::Win32::System::Com::IStream](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/struct.IStream.html)
interface backed by a temp file on disk. The temp file is created with
[SHCreateStreamOnFileEx](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/UI/Shell/fn.SHCreateStreamOnFileEx.html), using
[FILE_ATTRIBUTE_TEMPORARY](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Storage/FileSystem/constant.FILE_ATTRIBUTE_TEMPORARY.html) and [FILE_FLAG_DELETE_ON_CLOSE](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Storage/FileSystem/constant.FILE_FLAG_DELETE_ON_CLOSE.html)
so it will be deleted by the OS as soon as the last reference to the `IStream` is dropped.

It is intended as an alternative to [SHCreateMemStream](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/UI/Shell/fn.SHCreateMemStream.html)
or [CreateStreamOnHGlobal](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/StructuredStorage/fn.CreateStreamOnHGlobal.html),
both of which will hold the entire stream in memory.
