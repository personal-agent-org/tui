//! Cancellable private pipe/socket handoff. No blocking stdin thread is started.
use super::{ReadError, SessionToken};
use rustix::fs::{fcntl_getfl, fcntl_setfl, fstat, FileType, OFlags};
use std::{
    fs::File,
    io::Read,
    os::fd::{AsRawFd, OwnedFd, RawFd},
    time::Duration,
};
use zeroize::Zeroizing;

struct NonblockingPipe {
    file: File,
    original_flags: OFlags,
}

impl AsRawFd for NonblockingPipe {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Drop for NonblockingPipe {
    fn drop(&mut self) {
        // fcntl changes the shared open-file-description. Restore even on timeout,
        // invalid token, registration error, or cancellation/drop of the read future.
        let _ = fcntl_setfl(&self.file, self.original_flags);
    }
}

pub(super) async fn read_pipe(fd: OwnedFd, deadline: Duration) -> Result<SessionToken, ReadError> {
    SessionToken::from_bytes(read_private(fd, deadline, 67).await?)
}

/// Reads at most `limit` bytes of one secret from an explicitly selected private pipe.
///
/// The ceiling is the same refusal the session handoff already had: more bytes than the
/// caller declared is a wrong pipe, not a value to truncate. EOF is the only terminator,
/// so a writer that never closes times out instead of leaving the command waiting.
pub(super) async fn read_private(
    fd: OwnedFd,
    deadline: Duration,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, ReadError> {
    let kind = FileType::from_raw_mode(
        fstat(&fd)
            .map_err(|_| ReadError::InvalidSessionHandoff)?
            .st_mode,
    );
    if !matches!(kind, FileType::Fifo | FileType::Socket) {
        return Err(ReadError::InvalidSessionHandoff);
    }
    let original_flags = fcntl_getfl(&fd).map_err(|_| ReadError::InvalidSessionHandoff)?;
    let pipe = NonblockingPipe {
        file: File::from(fd),
        original_flags,
    };
    fcntl_setfl(&pipe.file, original_flags | OFlags::NONBLOCK)
        .map_err(|_| ReadError::InvalidSessionHandoff)?;
    let pipe = tokio::io::unix::AsyncFd::new(pipe).map_err(|_| ReadError::InvalidSessionHandoff)?;
    tokio::time::timeout(deadline, async {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut chunk = Zeroizing::new(vec![0_u8; limit]);
        loop {
            if bytes.len() == limit {
                return Err(ReadError::InvalidSessionHandoff);
            }
            let mut ready = pipe
                .readable()
                .await
                .map_err(|_| ReadError::InvalidSessionHandoff)?;
            let remaining = limit - bytes.len();
            match ready.try_io(|inner| (&inner.get_ref().file).read(&mut chunk[..remaining])) {
                Ok(Ok(0)) => return Ok(bytes),
                Ok(Ok(length)) => bytes.extend_from_slice(&chunk[..length]),
                Ok(Err(_)) => return Err(ReadError::InvalidSessionHandoff),
                Err(_) => {}
            }
        }
    })
    .await
    .map_err(|_| ReadError::InvalidSessionHandoff)?
}
