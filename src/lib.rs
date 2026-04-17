#![deny(unsafe_op_in_unsafe_fn)]

//! ACP (Authenticated Channel Protocol) - FFI bindings for secure communication.
//!
//! This library provides C-compatible FFI functions for establishing encrypted
//! sessions with forward secrecy and replay protection.

pub mod error;
pub mod frame;
pub mod handshake;
pub mod ratchet;
pub mod session;
pub mod api;

pub use crate::error::AcpResult;
pub use api::AcpSession;
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
        return Err(AcpError::invalid_argument("session is null"));
    }
    Ok(unsafe { &mut *(session as *mut SessionHandle) })
}

unsafe fn read_input<'a>(ptr_in: *const u8, len: u32) -> Result<&'a [u8], AcpError> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr_in.is_null() {
        return Err(AcpError::invalid_argument("input pointer is null"));
    }
    Ok(unsafe { slice::from_raw_parts(ptr_in, len as usize) })
}

unsafe fn read_fixed_32(ptr_in: *const u8, len: u32, name: &'static str) -> Result<[u8; 32], AcpError> {
    if len != 32 {
        return Err(AcpError::invalid_argument(name));
    }
    if ptr_in.is_null() {
        return Err(AcpError::invalid_argument(name));
    }
    let mut out = [0u8; 32];
    unsafe { ptr::copy_nonoverlapping(ptr_in, out.as_mut_ptr(), 32) };
    Ok(out)
}

unsafe fn write_output(out: *mut u8, out_len: *mut u32, data: &[u8]) -> Result<(), AcpError> {
    if out_len.is_null() {
        return Err(AcpError::invalid_argument("out_len is null"));
    }
    let required = u32::try_from(data.len()).map_err(|_| AcpError::internal_error("output too large"))?;
    let capacity = unsafe { *out_len as usize };

    if data.is_empty() {
        unsafe { *out_len = 0 };
        return Ok(());
    }

    if out.is_null() || capacity < data.len() {
        unsafe { *out_len = required };
        return Err(AcpError::BufferTooSmall(data.len()));
    }

    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), out, data.len()) };
    unsafe { *out_len = required };
    Ok(())
}

unsafe fn ensure_output_capacity(
    out: *mut u8,
    out_len: *mut u32,
    needed: usize,
) -> Result<(), AcpError> {
    if out_len.is_null() {
        return Err(AcpError::invalid_argument("out_len is null"));
    }
    let needed_u32 =
        u32::try_from(needed).map_err(|_| AcpError::internal_error("output too large"))?;
    let capacity = unsafe { *out_len as usize };
    if out.is_null() || capacity < needed {
        unsafe { *out_len = needed_u32 };
        return Err(AcpError::BufferTooSmall(needed));
    }
    Ok(())
}

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
pub extern "C" fn acp_session_free(session: *mut AcpSessionOpaque) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if session.is_null() {
            return;
        }
        unsafe { drop(Box::from_raw(session as *mut SessionHandle)) };
        clear_last_error();
    }));
}

#[unsafe(no_mangle)]
pub extern "C" fn acp_session_set_local_signing_key(
    session: *mut AcpSessionOpaque,
    sk: *const u8,
    sk_len: u32,
) -> AcpResult {
    run_ffi(|| {
        let key = unsafe { read_fixed_32(sk, sk_len, "local signing key must be 32 bytes") }?;
        let s = unsafe { session_from_ptr_mut(session) }?;
        s.set_local_signing_key(key)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn acp_session_set_remote_verifying_key(
    session: *mut AcpSessionOpaque,
    pk: *const u8,
    pk_len: u32,
) -> AcpResult {
    run_ffi(|| {
        let key = unsafe { read_fixed_32(pk, pk_len, "remote verifying key must be 32 bytes") }?;
        let s = unsafe { session_from_ptr_mut(session) }?;
        s.set_remote_verifying_key(key)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn acp_handshake_initiate(
    session: *mut AcpSessionOpaque,
    out_payload: *mut u8,
    out_len: *mut u32,
) -> AcpResult {
    run_ffi(|| {
        let s = unsafe { session_from_ptr_mut(session) }?;
        let needed = s.preview_handshake_initiate_len()?;
        unsafe { ensure_output_capacity(out_payload, out_len, needed) }?;
        let payload = s.handshake_initiate()?;
        unsafe { write_output(out_payload, out_len, &payload) }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn acp_handshake_respond(
    session: *mut AcpSessionOpaque,
    input: *const u8,
    in_len: u32,
    out: *mut u8,
    out_len: *mut u32,
) -> AcpResult {
    run_ffi(|| {
        let s = unsafe { session_from_ptr_mut(session) }?;
        let input = unsafe { read_input(input, in_len) }?;
        let needed = s.preview_handshake_respond_len(input)?;
        unsafe { ensure_output_capacity(out, out_len, needed) }?;
        let payload = s.handshake_respond(input)?;
        unsafe { write_output(out, out_len, &payload) }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn acp_handshake_finalize(
    session: *mut AcpSessionOpaque,
    input: *const u8,
    in_len: u32,
) -> AcpResult {
    run_ffi(|| {
        let s = unsafe { session_from_ptr_mut(session) }?;
        let input = unsafe { read_input(input, in_len) }?;
        s.handshake_finalize(input)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn acp_encrypt(
    session: *mut AcpSessionOpaque,
    pt: *const u8,
    pt_len: u32,
    out: *mut u8,
    out_len: *mut u32,
) -> AcpResult {
    run_ffi(|| {
        let s = unsafe { session_from_ptr_mut(session) }?;
        let pt = unsafe { read_input(pt, pt_len) }?;
        let needed = s.preview_encrypt_len(pt.len())?;
        unsafe { ensure_output_capacity(out, out_len, needed) }?;
        let ct = s.encrypt(pt)?;
        unsafe { write_output(out, out_len, &ct) }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn acp_decrypt(
    session: *mut AcpSessionOpaque,
    ct: *const u8,
    ct_len: u32,
    out: *mut u8,
    out_len: *mut u32,
) -> AcpResult {
    run_ffi(|| {
        let s = unsafe { session_from_ptr_mut(session) }?;
        let ct = unsafe { read_input(ct, ct_len) }?;
        let needed = s.preview_decrypt_len(ct)?;
        unsafe { ensure_output_capacity(out, out_len, needed) }?;
        let pt = s.decrypt(ct)?;
        unsafe { write_output(out, out_len, &pt) }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn acp_last_error(out: *mut u8, out_len: *mut u32) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if out_len.is_null() {
            return;
        }
        let msg = LAST_ERROR.with(|slot| slot.borrow().clone());
        let mut bytes = msg.into_bytes();
        bytes.push(0);
        let required = u32::try_from(bytes.len()).unwrap_or(u32::MAX);

        let capacity = unsafe { *out_len as usize };
        if out.is_null() || capacity < bytes.len() {
            unsafe { *out_len = required };
            return;
        }
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
        unsafe { *out_len = required };
    }));
}
