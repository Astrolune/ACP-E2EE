using System;
using System.Runtime.InteropServices;

namespace Acp.Interop
{
    public enum AcpResult : int
    {
        Ok = 0,
        InvalidArgument = 1,
        BufferTooSmall = 2,
        InvalidState = 3,
        ParseError = 4,
        VerifyFailed = 5,
        ReplayDetected = 6,
        CryptoError = 7,
        InternalError = 8,
        Panic = 9
    }

    internal static class Native
    {
        private const string DllName = "acp";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr acp_session_new();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void acp_session_free(IntPtr session);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern AcpResult acp_session_set_local_signing_key(
            IntPtr session, byte[] sk, uint sk_len);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern AcpResult acp_session_set_remote_verifying_key(
            IntPtr session, byte[] pk, uint pk_len);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern AcpResult acp_handshake_initiate(
            IntPtr session, IntPtr out_payload, ref uint out_len);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern AcpResult acp_handshake_respond(
            IntPtr session, byte[] input, uint in_len, IntPtr out_payload, ref uint out_len);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern AcpResult acp_handshake_finalize(
            IntPtr session, byte[] input, uint in_len);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern AcpResult acp_encrypt(
            IntPtr session, byte[] pt, uint pt_len, IntPtr out_buf, ref uint out_len);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern AcpResult acp_decrypt(
            IntPtr session, byte[] ct, uint ct_len, IntPtr out_buf, ref uint out_len);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void acp_last_error(IntPtr out_buf, ref uint out_len);
    }

    public sealed class AcpSession : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        public AcpSession()
        {
            _handle = Native.acp_session_new();
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException($"acp_session_new failed: {GetLastError()}");
            }
        }

        /// <summary>
        /// Sets Ed25519 private seed (32 bytes). This maps to ed25519-dalek SigningKey::from_bytes(seed32).
        /// The seed is zeroed after use for security.
        /// </summary>
        public void SetLocalSigningSeed(byte[] seed32)
        {
            EnsureNotDisposed();
            if (seed32 == null || seed32.Length != 32)
            {
                throw new ArgumentException("Signing seed must be exactly 32 bytes.", nameof(seed32));
            }
            try
            {
                ThrowOnError(Native.acp_session_set_local_signing_key(_handle, seed32, 32));
            }
            finally
            {
                // Zero the seed after use to prevent it from lingering in managed memory
                Array.Clear(seed32, 0, seed32.Length);
            }
        }

        [Obsolete("Use SetLocalSigningSeed instead.")]
        public void SetLocalSigningKey(byte[] secret32) => SetLocalSigningSeed(secret32);

        public void SetRemoteVerifyingKey(byte[] public32)
        {
            EnsureNotDisposed();
            if (public32 == null || public32.Length != 32)
            {
                throw new ArgumentException("Verifying key must be exactly 32 bytes.", nameof(public32));
            }
            ThrowOnError(Native.acp_session_set_remote_verifying_key(_handle, public32, 32));
        }

        public byte[] HandshakeInitiate()
        {
            EnsureNotDisposed();
            return CallWithOutput((buffer, ref uint len) => Native.acp_handshake_initiate(_handle, buffer, ref len));
        }

        public byte[] HandshakeRespond(byte[] input)
        {
            EnsureNotDisposed();
            if (input == null) throw new ArgumentNullException(nameof(input));
            return CallWithOutput(
                (buffer, ref uint len) => Native.acp_handshake_respond(_handle, input, (uint)input.Length, buffer, ref len)
            );
        }

        public void HandshakeFinalize(byte[] input)
        {
            EnsureNotDisposed();
            if (input == null) throw new ArgumentNullException(nameof(input));
            ThrowOnError(Native.acp_handshake_finalize(_handle, input, (uint)input.Length));
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            EnsureNotDisposed();
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            return CallWithOutput(
                (buffer, ref uint len) => Native.acp_encrypt(_handle, plaintext, (uint)plaintext.Length, buffer, ref len)
            );
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            EnsureNotDisposed();
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            return CallWithOutput(
                (buffer, ref uint len) => Native.acp_decrypt(_handle, ciphertext, (uint)ciphertext.Length, buffer, ref len)
            );
        }

        /// <summary>
        /// Retrieves the last error message from the current thread.
        ///
        /// WARNING: This is thread-local. In async C# code, if a context switch occurs
        /// between the FFI call and this method, the error may be lost or incorrect.
        /// Always call this immediately after an error on the same thread.
        /// </summary>
        public static string GetLastError()
        {
            uint len = 0;
            Native.acp_last_error(IntPtr.Zero, ref len);
            if (len == 0) return string.Empty;

            IntPtr buffer = Marshal.AllocHGlobal((int)len);
            try
            {
                Native.acp_last_error(buffer, ref len);
                byte[] bytes = new byte[len];
                Marshal.Copy(buffer, bytes, 0, (int)len);
                int nul = Array.IndexOf(bytes, (byte)0);
                int strLen = nul >= 0 ? nul : bytes.Length;
                return System.Text.Encoding.UTF8.GetString(bytes, 0, strLen);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            if (_handle != IntPtr.Zero)
            {
                Native.acp_session_free(_handle);
                _handle = IntPtr.Zero;
            }
            _disposed = true;
            GC.SuppressFinalize(this);
        }

        ~AcpSession() => Dispose();

        private void EnsureNotDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(AcpSession));
            }
        }

        private static void ThrowOnError(AcpResult result)
        {
            if (result == AcpResult.Ok) return;
            throw new InvalidOperationException($"ACP call failed: {result}; error: {GetLastError()}");
        }

        private delegate AcpResult OutputCall(IntPtr buffer, ref uint len);

        /// <summary>
        /// Calls an FFI function that returns output via a buffer.
        ///
        /// WARNING: For stateful operations (handshake), this calls the FFI function twice:
        /// once to probe size, once to get data. The Rust side protects against state
        /// changes via ensure_output_capacity, but this pattern is inherently fragile.
        /// </summary>
        private static byte[] CallWithOutput(OutputCall call)
        {
            uint len = 0;
            AcpResult probe = call(IntPtr.Zero, ref len);
            if (probe != AcpResult.BufferTooSmall && probe != AcpResult.Ok)
            {
                ThrowOnError(probe);
            }
            if (len == 0) return Array.Empty<byte>();

            IntPtr buffer = Marshal.AllocHGlobal((int)len);
            try
            {
                AcpResult result = call(buffer, ref len);
                ThrowOnError(result);
                byte[] output = new byte[len];
                Marshal.Copy(buffer, output, 0, (int)len);
                return output;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
