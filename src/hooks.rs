//! Pre/post cache/request hooks

use libloading::{Library, Symbol};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Deliver,
}

pub struct Hooks {
    dlh: Option<Library>,
}

impl Hooks {
    pub fn new<P: AsRef<Path>>(path: Option<P>) -> Self {
        let dlh = match path {
            None => None,
            Some(path) => match unsafe { Library::new(path.as_ref()) } {
                Err(err) => {
                    tracing::error!(
                        path = %path.as_ref().display(),
                        error = %err,
                        "Cannot load the hooks C library"
                    );
                    None
                }
                Ok(dlh) => Some(dlh),
            },
        };
        Hooks { dlh }
    }

    #[inline]
    pub fn enabled(&self, _stage: Stage) -> bool {
        self.dlh.is_some()
    }

    /// Apply the hook to the packet.
    /// The hook function in C should have the signature:
    /// size_t hook(uint8_t *packet, size_t length, size_t capacity);
    /// It should return the new length of the packet, or 0 to indicate no change or error.
    pub fn apply(&self, packet: Vec<u8>, _stage: Stage) -> Option<Vec<u8>> {
        let dlh = self.dlh.as_ref()?;

        unsafe {
            let hook_res: Result<Symbol<unsafe extern "C" fn(*mut u8, usize, usize) -> usize>, _> = dlh.get(b"hook");

            if let Ok(hook) = hook_res {
                let mut buf = packet;
                let original_len = buf.len();
                let capacity = buf.capacity();

                // The C hook can modify the packet in-place up to its capacity.
                let new_len = hook(buf.as_mut_ptr(), original_len, capacity);

                if new_len > 0 && new_len <= capacity {
                    buf.set_len(new_len);
                    return Some(buf);
                }
            }
        }

        None
    }
}
