use iso7816::Status;

pub fn status_from(error: trussed_core::Error) -> Status {
    match error {
        trussed_core::Error::FilesystemWriteFailure => Status::NotEnoughMemory,
        _ => Status::UnspecifiedNonpersistentExecutionError,
    }
}

macro_rules! syscall {
    ($call:expr) => {{
        match $call {
            Ok(mut future) => loop {
                if let core::task::Poll::Ready(result) = future.poll() {
                    break result.map_err($crate::syscall::status_from);
                }
            },
            Err(_) => Err(iso7816::Status::UnspecifiedNonpersistentExecutionError),
        }
    }};
}
