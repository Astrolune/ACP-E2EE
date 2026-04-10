#![deny(unsafe_op_in_unsafe_fn)]

pub mod error;
pub mod frame;
pub mod handshake;
pub mod ratchet;
pub mod session;

pub use crate::error::AcpResult;
use crate::error::AcpError;
use crate::session::SessionHandle;
use core::{ptr, slice};
use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[repr(C)]
pub struct AcpSessionOpaque {
    _private: [u8; 0],
}

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_last_error(message: impl Into<String>) {
    let msg = message.into();
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = msg;
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        slot.borrow_mut().clear();
    });
}

fn run_ffi<F>(op: F) -> AcpResult
where
    F: FnOnce() -> Result<(), AcpError>,
{
    match catch_unwind(AssertUnwindSafe(op)) {
        Ok(Ok(())) => {
            clear_last_error();
            AcpResult::Ok
        }
        Ok(Err(err)) => {
            set_last_error(err.to_string());
            err.result_code()
        }
        Err(_) => {
            set_last_error("panic across FFI boundary was blocked");
            AcpResult::Panic
        }
    }
}

unsafe fn session_from_ptr_mut<'a>(
    session: *mut AcpSessionOpaque,
) -> Result<&'a mut SessionHandle, AcpError> {
    if session.is_null() {
        return Err(AcpError::InvalidArgument("session is null"));
    }
    // SAFETY: caller provided a non-null pointer originating from `acp_session_new`.
    Ok(unsafe { &mut *(session as *mut SessionHandle) })
}

unsafe fn read_input<'a>(ptr_in: *const u8, len: u32) -> Result<&'a [u8], AcpError> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr_in.is_null() {
        return Err(AcpError::InvalidArgument("input pointer is null"));
    }
    // SAFETY: pointer validity is required by FFI contract and length has been checked.
    Ok(unsafe { slice::from_raw_parts(ptr_in, len as usize) })
}

unsafe fn read_fixed_32(ptr_in: *const u8, len: u32, name: &'static str) -> Result<[u8; 32], AcpError> {
    if len != 32 {
        return Err(AcpError::InvalidArgument(name));
    }
    if ptr_in.is_null() {
        return Err(AcpError::InvalidArgument(name));
    }
    let mut out = [0u8; 32];
    // SAFETY: pointer validity and exact length were checked above.
    unsafe { ptr::copy_nonoverlapping(ptr_in, out.as_mut_ptr(), 32) };
    Ok(out)
}

unsafe fn write_output(out: *mut u8, out_len: *mut u32, data: &[u8]) -> Result<(), AcpError> {
    if out_len.is_null() {
        return Err(AcpError::InvalidArgument("out_len is null"));
    }
    let required = u32::try_from(data.len()).map_err(|_| AcpError::InternalError("output too large"))?;
    // SAFETY: out_len was checked for non-null above.
    let capacity = unsafe { *out_len as usize };

    if data.is_empty() {
        // SAFETY: out_len was checked for non-null above.
        unsafe { *out_len = 0 };
        return Ok(());
    }

    if out.is_null() || capacity < data.len() {
        // SAFETY: out_len was checked for non-null above.
        unsafe { *out_len = required };
        return Err(AcpError::BufferTooSmall(data.len()));
    }

    // SAFETY: destination has sufficient capacity and both pointers are valid.
    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), out, data.len()) };
    // SAFETY: out_len was checked for non-null above.
    unsafe { *out_len = required };
    Ok(())
}

unsafe fn ensure_output_capacity(
    out: *mut u8,
    out_len: *mut u32,
    needed: usize,
) -> Result<(), AcpError> {
    if out_len.is_null() {
        return Err(AcpError::InvalidArgument("out_len is null"));
    }
    let needed_u32 =
        u32::try_from(needed).map_err(|_| AcpError::InternalError("output too large"))?;
    // SAFETY: out_len was checked for non-null above.
    let capacity = unsafe { *out_len as usize };
    if out.is_null() || capacity < needed {
        // SAFETY: out_len was checked for non-null above.
        unsafe { *out_len = needed_u32 };
        return Err(AcpError::BufferTooSmall(needed));
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn acp_session_new() -> *mut AcpSessionOpaque {
    match catch_unwind(AssertUnwindSafe(|| -> Result<*mut AcpSessionOpaque, AcpError> {
        let boxed = Box::new(SessionHandle::new());
        let raw = Box::into_raw(boxed) as *mut AcpSessionOpaque;
        Ok(raw)
    })) {
        Ok(Ok(ptr_out)) => {
            clear_last_error();
            ptr_out
        }
        Ok(Err(err)) => {
            set_last_error(err.to_string());
            ptr::null_mut()
        }
        Err(_) => {
            set_last_error("panic across FFI boundary was blocked");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn acp_session_free(session: *mut AcpSessionOpaque) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if session.is_null() {
            return;
        }
        // SAFETY: pointer is expected to originate from `acp_session_new`.
        unsafe { drop(Box::from_raw(session as *mut SessionHandle)) };
        clear_last_error();
    }));
}

#[no_mangle]
pub extern "C" fn acp_session_set_local_signing_key(
    session: *mut AcpSessionOpaque,
    sk: *const u8,
    sk_len: u32,
) -> AcpResult {
    run_ffi(|| {
        // SAFETY: validates pointers/lengths and only reads fixed-size input.
        let key = unsafe { read_fixed_32(sk, sk_len, "local signing key must be 32 bytes") }?;
        // SAFETY: validates and converts opaque session pointer.
        let s = unsafe { session_from_ptr_mut(session) }?;
        s.set_local_signing_key(key)
    })
}

#[no_mangle]
pub extern "C" fn acp_session_set_remote_verifying_key(
    session: *mut AcpSessionOpaque,
    pk: *const u8,
    pk_len: u32,
) -> AcpResult {
    run_ffi(|| {
        // SAFETY: validates pointers/lengths and only reads fixed-size input.
        let key = unsafe { read_fixed_32(pk, pk_len, "remote verifying key must be 32 bytes") }?;
        // SAFETY: validates and converts opaque session pointer.
        let s = unsafe { session_from_ptr_mut(session) }?;
        s.set_remote_verifying_key(key)
    })
}

#[no_mangle]
pub extern "C" fn acp_handshake_initiate(
    session: *mut AcpSessionOpaque,
    out_payload: *mut u8,
    out_len: *mut u32,
) -> AcpResult {
    run_ffi(|| {
        // SAFETY: validates and converts opaque session pointer.
        let s = unsafe { session_from_ptr_mut(session) }?;
        let needed = s.preview_handshake_initiate_len()?;
        // SAFETY: output pointers handled according to FFI contract.
        unsafe { ensure_output_capacity(out_payload, out_len, needed) }?;
        let payload = s.handshake_initiate()?;
        // SAFETY: output pointers handled according to FFI contract.
        unsafe { write_output(out_payload, out_len, &payload) }
    })
}

#[no_mangle]
pub extern "C" fn acp_handshake_respond(
    session: *mut AcpSessionOpaque,
    input: *const u8,
    in_len: u32,
    out: *mut u8,
    out_len: *mut u32,
) -> AcpResult {
    run_ffi(|| {
        // SAFETY: validates and converts opaque session pointer.
        let s = unsafe { session_from_ptr_mut(session) }?;
        // SAFETY: validates input pointer/len and creates read-only slice.
        let input = unsafe { read_input(input, in_len) }?;
        let needed = s.preview_handshake_respond_len(input)?;
        // SAFETY: output pointers handled according to FFI contract.
        unsafe { ensure_output_capacity(out, out_len, needed) }?;
        let payload = s.handshake_respond(input)?;
        // SAFETY: output pointers handled according to FFI contract.
        unsafe { write_output(out, out_len, &payload) }
    })
}

#[no_mangle]
pub extern "C" fn acp_handshake_finalize(
    session: *mut AcpSessionOpaque,
    input: *const u8,
    in_len: u32,
) -> AcpResult {
    run_ffi(|| {
        // SAFETY: validates and converts opaque session pointer.
        let s = unsafe { session_from_ptr_mut(session) }?;
        // SAFETY: validates input pointer/len and creates read-only slice.
        let input = unsafe { read_input(input, in_len) }?;
        s.handshake_finalize(input)
    })
}

#[no_mangle]
pub extern "C" fn acp_encrypt(
    session: *mut AcpSessionOpaque,
    pt: *const u8,
    pt_len: u32,
    out: *mut u8,
    out_len: *mut u32,
) -> AcpResult {
    run_ffi(|| {
        // SAFETY: validates and converts opaque session pointer.
        let s = unsafe { session_from_ptr_mut(session) }?;
        // SAFETY: validates input pointer/len and creates read-only slice.
        let pt = unsafe { read_input(pt, pt_len) }?;
        let needed = s.preview_encrypt_len(pt.len())?;
        // SAFETY: output pointers handled according to FFI contract.
        unsafe { ensure_output_capacity(out, out_len, needed) }?;
        let ct = s.encrypt(pt)?;
        // SAFETY: output pointers handled according to FFI contract.
        unsafe { write_output(out, out_len, &ct) }
    })
}

#[no_mangle]
pub extern "C" fn acp_decrypt(
    session: *mut AcpSessionOpaque,
    ct: *const u8,
    ct_len: u32,
    out: *mut u8,
    out_len: *mut u32,
) -> AcpResult {
    run_ffi(|| {
        // SAFETY: validates and converts opaque session pointer.
        let s = unsafe { session_from_ptr_mut(session) }?;
        // SAFETY: validates input pointer/len and creates read-only slice.
        let ct = unsafe { read_input(ct, ct_len) }?;
        let needed = s.preview_decrypt_len(ct)?;
        // SAFETY: output pointers handled according to FFI contract.
        unsafe { ensure_output_capacity(out, out_len, needed) }?;
        let pt = s.decrypt(ct)?;
        // SAFETY: output pointers handled according to FFI contract.
        unsafe { write_output(out, out_len, &pt) }
    })
}

#[no_mangle]
pub extern "C" fn acp_last_error(out: *mut u8, out_len: *mut u32) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if out_len.is_null() {
            return;
        }
        let msg = LAST_ERROR.with(|slot| slot.borrow().clone());
        let mut bytes = msg.into_bytes();
        bytes.push(0);
        let required = u32::try_from(bytes.len()).unwrap_or(u32::MAX);

        // SAFETY: out_len is non-null by check above.
        let capacity = unsafe { *out_len as usize };
        if out.is_null() || capacity < bytes.len() {
            // SAFETY: out_len is non-null by check above.
            unsafe { *out_len = required };
            return;
        }
        // SAFETY: destination has sufficient capacity and pointers are valid by contract.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
        // SAFETY: out_len is non-null by check above.
        unsafe { *out_len = required };
    }));
}
