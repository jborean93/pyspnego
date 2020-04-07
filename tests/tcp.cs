using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Pyspnego
{
    internal class NativeHelpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;

            public static explicit operator UInt64(LUID l)
            {
                return (UInt64)((UInt64)l.HighPart << 32) | (UInt64)l.LowPart;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public PrivilegeAttributes Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SecBufferDesc : IDisposable
        {
            public UInt32 ulVersion;
            public UInt32 cBuffers;
            public IntPtr pBuffers {
                get { return this._buffer.DangerousGetHandle(); }
            }

            private SafeMemoryBuffer _buffer;

            public SecBufferDesc(List<SecurityBuffer> buffers)
            {
                cBuffers = (UInt32)buffers.Count;
                _buffer = new SafeMemoryBuffer(IntPtr.Zero);

                if (cBuffers > 0)
                {
                    int bufferLength = Marshal.SizeOf(typeof(SecBuffer));
                    int bufferDataOffset = bufferLength * buffers.Count;
                    int bufferDataLength = buffers.Sum(i => i.Data == null ? 0 : i.Data.Length);

                    _buffer = new SafeMemoryBuffer(bufferDataOffset + bufferDataLength);
                    IntPtr inputBufferPtr = _buffer.DangerousGetHandle();
                    IntPtr inputBufferDataPtr = IntPtr.Add(inputBufferPtr, bufferDataOffset);

                    foreach (SecurityBuffer buffer in buffers)
                    {
                        SecBuffer bufferElement = new SecBuffer()
                        {
                            BufferType = buffer.BufferType,
                        };

                        if (buffer.Data == null)
                        {
                            bufferElement.cbBuffer = 0;
                            bufferElement.pvBuffer = IntPtr.Zero;
                        }
                        else
                        {
                            bufferElement.cbBuffer = buffer.Data.Length;
                            bufferElement.pvBuffer = inputBufferDataPtr;
                            Marshal.Copy(buffer.Data, 0, inputBufferDataPtr, buffer.Data.Length);
                            inputBufferDataPtr = IntPtr.Add(inputBufferDataPtr, buffer.Data.Length);
                        }

                        Marshal.StructureToPtr(bufferElement, inputBufferPtr, false);
                        inputBufferPtr = IntPtr.Add(inputBufferPtr, bufferLength);
                    }
                }
            }

            public static explicit operator List<SecurityBuffer>(SecBufferDesc b)
            {
                List<SecurityBuffer> buffers = new List<SecurityBuffer>();
                if (b.cBuffers == 0)
                    return buffers;

                for (int i = 0; i < b.cBuffers; i++)
                {
                    SecBuffer entry = (SecBuffer)Marshal.PtrToStructure(
                        IntPtr.Add(b.pBuffers, i * Marshal.SizeOf(typeof(SecBuffer))), typeof(SecBuffer));

                    byte[] entryData = new byte[entry.cbBuffer];
                    Marshal.Copy(entry.pvBuffer, entryData, 0, entry.cbBuffer);

                    buffers.Add(new SecurityBuffer()
                    {
                        BufferType = entry.BufferType,
                        Data = entryData,
                    });
                }

                return buffers;
            }

            public void Dispose()
            {
                _buffer.Dispose();
                GC.SuppressFinalize(this);
            }
            ~SecBufferDesc() { this.Dispose(); }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SecBuffer
        {
            public Int32 cbBuffer;
            public BufferType BufferType;
            public IntPtr pvBuffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SecHandle
        {
            public UIntPtr dwLower;
            public UIntPtr dwUpper;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SecPkgContextSizes
        {
            public Int32 cbMaxToken;
            public Int32 cbMaxSignature;
            public Int32 cbBlockSize;
            public Int32 cbSecurityTrailer;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SecPkgInfoW
        {
            public Int32 fCapabilities;
            public Int16 wVersion;
            public Int16 wRPCID;
            public Int32 cbMaxToken;
            [MarshalAs(UnmanagedType.LPWStr)] public string Name;
            [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        public enum TokenInformationClass : uint
        {
            TokenUser = 1,
        }
    }

    internal class NativeMethods
    {
        [DllImport("Secur32.dll")]
        public static extern UInt32 AcceptSecurityContext(
            ServerCredential phCredential,
            IntPtr phContext,
            NativeHelpers.SecBufferDesc pInput,
            UInt32 fContextReq,
            UInt32 TargetDataRep,
            IntPtr phNewContext,
            NativeHelpers.SecBufferDesc pOutput,
            out UInt32 pfContextAttr,
            out Int64 ptsExpiry);

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        public static extern UInt32 AcquireCredentialsHandleW(
            [MarshalAs(UnmanagedType.LPWStr)] string pszPrincipal,
            [MarshalAs(UnmanagedType.LPWStr)] string pPackage,
            UInt32 fCredentialUse,
            IntPtr pvLogonId,
            IntPtr pAuthData,
            IntPtr pGetKeyFn,
            IntPtr pvGetKeyArgument,
            IntPtr phCredential,
            out Int64 ptsExpiry);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
            IntPtr NewState,
            UInt32 BufferLength,
            IntPtr PreviousState,
            out UInt32 ReturnLength);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(
            IntPtr hObject);

        [DllImport("Secur32.dll")]
        public static extern UInt32 CompleteAuthToken(
            IntPtr phContext,
            NativeHelpers.SecBufferDesc pToken);

        [DllImport("Secur32.dll")]
        public static extern UInt32 DecryptMessage(
            IntPtr phContext,
            NativeHelpers.SecBufferDesc pMessage,
            UInt32 MessageSeqNo,
            ref UInt32 pfQOP);

        [DllImport("Secur32.dll")]
        public static extern UInt32 DeleteSecurityContext(
            IntPtr phContext);

        [DllImport("Secur32.dll")]
        public static extern UInt32 EncryptMessage(
            IntPtr phContext,
            UInt32 fQOP,
            NativeHelpers.SecBufferDesc pMessage,
            UInt32 MessageSeqNo);

        [DllImport("Secur32.dll")]
        public static extern UInt32 FreeContextBuffer(
            IntPtr pvContextBuffer);

        [DllImport("Secur32.dll")]
        public static extern UInt32 FreeCredentialsHandle(
            IntPtr phCredential);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            NativeHelpers.TokenInformationClass TokenInformationClass,
            SafeMemoryBuffer TokenInformation,
            UInt32 TokenInformationLength,
            out UInt32 ReturnLength);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken);

        [DllImport("Advapi32.dll")]
        public static extern bool ImpersonateSelf(
            SecurityImpersonationLevel ImpersonationLevel);

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool LookupPrivilegeValueW(
            string lpSystemName,
            string lpName,
            ref NativeHelpers.LUID lpLuid);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern SafeNativeHandle OpenProcess(
            ProcessAccessFlags dwDesiredAccess,
            bool bInheritHandle,
            UInt32 dwProcessId);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            TokenAccessLevels DesiredAccess,
            out SafeNativeHandle TokenHandle);

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        public static extern UInt32 QueryContextAttributesW(
            IntPtr phContext,
            SecPackageAttribute ulAttribute,
            IntPtr pBuffer);

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        public static extern UInt32 QuerySecurityPackageInfoW(
            string pPackageName,
            ref IntPtr ppPackageInfo);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();
    }

    internal class SafeMemoryBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeMemoryBuffer() : base(true) { }
        public SafeMemoryBuffer(int cb) : base(true)
        {
            base.SetHandle(Marshal.AllocHGlobal(cb));
        }
        public SafeMemoryBuffer(IntPtr ptr) : base(true)
        {
            base.SetHandle(handle);
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    internal class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeNativeHandle() : base(true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(handle);
        }
    }

    public class Win32Exception : System.ComponentModel.Win32Exception
    {
        private string _msg;

        public Win32Exception(string message) : this(Marshal.GetLastWin32Error(), message) { }
        public Win32Exception(int errorCode, string message) : base(errorCode)
        {
            _msg = String.Format("{0} ({1}, Win32ErrorCode {2} - 0x{2:X8})", message, base.Message, errorCode);
        }

        public override string Message { get { return _msg; } }
        public static explicit operator Win32Exception(string message) { return new Win32Exception(message); }
    }

    public class ServerCredential : SafeHandleZeroOrMinusOneIsInvalid
    {
        private bool _initialized = false;

        public Int64 Expiry;
        public SecurityPackageInfo PackageInfo;

        public ServerCredential(string package) : base(true)
        {
            base.SetHandle(Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeHelpers.SecHandle))));

            UInt32 res = NativeMethods.AcquireCredentialsHandleW(
                null,
                package,
                0x00000001,  // SECPKG_CRED_INBOUND
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                this.handle,
                out Expiry);

            if (res != 0)
                throw new Exception(String.Format("AcquireCredentialsHandleW() failed {0} - 0x{0:X8}", res));
            _initialized = true;

            PackageInfo = QuerySecurityPackageInfo(package);
        }

        private static SecurityPackageInfo QuerySecurityPackageInfo(string package)
        {
            IntPtr pkgInfo = IntPtr.Zero;
            UInt32 res = NativeMethods.QuerySecurityPackageInfoW(package, ref pkgInfo);
            if (res != 0)
                throw new Exception(String.Format("QuerySecurityPackageInfoW() failed {0} - 0x{0:X8}", res));

            try
            {
                NativeHelpers.SecPkgInfoW rawInfo = (NativeHelpers.SecPkgInfoW)Marshal.PtrToStructure(pkgInfo,
                    typeof(NativeHelpers.SecPkgInfoW));

                return new SecurityPackageInfo()
                {
                    Capabilities = rawInfo.fCapabilities,
                    Version = rawInfo.wVersion,
                    RPCID = rawInfo.wRPCID,
                    MaxToken = rawInfo.cbMaxToken,
                    Name = rawInfo.Name,
                    Comment = rawInfo.Comment,
                };
            }
            finally
            {
                NativeMethods.FreeContextBuffer(pkgInfo);
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            if (_initialized)
                NativeMethods.FreeCredentialsHandle(this.handle);

            Marshal.FreeHGlobal(this.handle);

            return true;
        }
    }

    public class SecurityContext : SafeHandleZeroOrMinusOneIsInvalid
    {
        private UInt32 SEC_E_OK = 0x00000000;
        private UInt32 SEC_I_COMPLETE_AND_CONTINUE = 0x00090314;
        private UInt32 SEC_I_COMPLETE_NEEDED = 0x00090313;
        private UInt32 SEC_I_CONTINUE_NEEDED = 0x00090312;

        private ServerCredential _credential;
        private bool _initialized = false;
        private UInt32 _sequenceEncrypt = 0;
        private UInt32 _sequenceDecrypt = 0;
        private int _trailerSize;
        private int _blockSize;

        public bool Complete = false;
        public UInt32 ContextAttributes;
        public Int64 Expiry;

        public SecurityContext(ServerCredential credential) : base(true)
        {
            this._credential = credential;
            base.SetHandle(Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeHelpers.SecHandle))));
        }

        public byte[] Step(byte[] token)
        {
            List<SecurityBuffer> input = new List<SecurityBuffer>()
            {
                new SecurityBuffer()
                {
                    BufferType = BufferType.Token,
                    Data = token,
                },
            };

            List<SecurityBuffer> output = new List<SecurityBuffer>()
            {
                new SecurityBuffer()
                {
                    BufferType = BufferType.Token,
                    Data = new byte[_credential.PackageInfo.MaxToken],
                },
            };

            using (NativeHelpers.SecBufferDesc inputBuffer = new NativeHelpers.SecBufferDesc(input))
            using (NativeHelpers.SecBufferDesc outputBuffer = new NativeHelpers.SecBufferDesc(output))
            {
                UInt32 res = NativeMethods.AcceptSecurityContext(
                    _credential,
                    _initialized ? this.handle : IntPtr.Zero,
                    inputBuffer,
                    0,
                    0x00000010,  // SECURITY_NATIVE_DREP
                    this.handle,
                    outputBuffer,
                    out ContextAttributes,
                    out Expiry);

                _initialized = true;

                if (new List<UInt32>() { SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED }.Contains(res))
                    res = NativeMethods.CompleteAuthToken(this.handle, outputBuffer);

                if (res == SEC_E_OK)
                {
                    Complete = true;
                    GetSecPkgSizes();
                }
                else if (res != SEC_I_CONTINUE_NEEDED)
                    throw new Exception(String.Format("AcceptSecurityContext() failed {0} - 0x{0:X8}", res));

                output = (List<SecurityBuffer>)outputBuffer;
                return output[0].Data;
            }
        }

        public byte[] Unwrap(byte[] data)
        {
            List<SecurityBuffer> input = new List<SecurityBuffer>()
            {
                new SecurityBuffer()
                {
                    BufferType = BufferType.Stream,
                    Data = data,
                },
                new SecurityBuffer()
                {
                    BufferType = BufferType.Data,
                    Data = null,
                },
            };

            using (NativeHelpers.SecBufferDesc inputInfo = new NativeHelpers.SecBufferDesc(input))
            {
                UInt32 qop = 0;
                UInt32 res = NativeMethods.DecryptMessage(this.handle, inputInfo, _sequenceDecrypt, ref qop);
                if (res != SEC_E_OK)
                    throw new Exception(String.Format("DecryptMessage() failed {0} - 0x{0:X8}", res));
                _sequenceDecrypt++;

                List<SecurityBuffer> output = (List<SecurityBuffer>)inputInfo;
                return output[1].Data;
            }
        }

        public byte[] Wrap(byte[] data)
        {
            List<SecurityBuffer> input = new List<SecurityBuffer>()
            {
                new SecurityBuffer()
                {
                    BufferType = BufferType.Token,
                    Data = new byte[_trailerSize],
                },
                new SecurityBuffer()
                {
                    BufferType = BufferType.Data,
                    Data = data,
                },
                new SecurityBuffer()
                {
                    BufferType = BufferType.Padding,
                    Data = new byte[_blockSize],
                },
            };

            using (NativeHelpers.SecBufferDesc inputInfo = new NativeHelpers.SecBufferDesc(input))
            {
                UInt32 res = NativeMethods.EncryptMessage(this.handle, 0, inputInfo, _sequenceEncrypt);
                if (res != SEC_E_OK)
                    throw new Exception(String.Format("DecryptMessage() failed {0} - 0x{0:X8}", res));
                _sequenceEncrypt++;

                List<SecurityBuffer> output = (List<SecurityBuffer>)inputInfo;

                byte[] encData = new byte[output.Sum(i => i.Data.Length)];
                int offset = 0;
                foreach (SecurityBuffer buffer in output)
                {
                    Buffer.BlockCopy(buffer.Data, 0, encData, offset, buffer.Data.Length);
                    offset += buffer.Data.Length;
                }

                return encData;
            }
        }

        private void GetSecPkgSizes()
        {
            using (SafeMemoryBuffer sizePtr = new SafeMemoryBuffer(Marshal.SizeOf(
                typeof(NativeHelpers.SecPkgContextSizes))))
            {
                UInt32 res = NativeMethods.QueryContextAttributesW(this.handle, SecPackageAttribute.Sizes,
                    sizePtr.DangerousGetHandle());
                if (res != SEC_E_OK)
                    throw new Exception(String.Format("QueryContextAttributesW() failed {0} - 0x{0:X8}", res));

                NativeHelpers.SecPkgContextSizes sizes = (NativeHelpers.SecPkgContextSizes)Marshal.PtrToStructure(
                    sizePtr.DangerousGetHandle(), typeof(NativeHelpers.SecPkgContextSizes));

                _blockSize = sizes.cbBlockSize;
                _trailerSize = sizes.cbSecurityTrailer;
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            if (_initialized)
                NativeMethods.DeleteSecurityContext(this.handle);

            Marshal.FreeHGlobal(this.handle);

            return true;
        }
    }

    public class PrivilegeEnabler : IDisposable
    {
        public PrivilegeEnabler(params string[] privileges)
        {
            int tokenPrivLength = Marshal.SizeOf(typeof(NativeHelpers.TOKEN_PRIVILEGES));
            int luidAttrLength = luidAttrLength = Marshal.SizeOf(
                typeof(NativeHelpers.LUID_AND_ATTRIBUTES)) * (privileges.Length - 1);

            byte[] newStateBytes = new byte[tokenPrivLength + luidAttrLength];
            using (SafeMemoryBuffer buffer = new SafeMemoryBuffer(tokenPrivLength + luidAttrLength))
            {
                IntPtr ptrOffset = buffer.DangerousGetHandle();
                NativeHelpers.TOKEN_PRIVILEGES tokenPrivileges = new NativeHelpers.TOKEN_PRIVILEGES()
                {
                    PrivilegeCount = (UInt32)privileges.Length,
                    Privileges = new NativeHelpers.LUID_AND_ATTRIBUTES[1],
                };
                tokenPrivileges.Privileges[0].Attributes = PrivilegeAttributes.Enabled;
                tokenPrivileges.Privileges[0].Luid = LookupPrivilegeValue(privileges[0]);

                Marshal.StructureToPtr(tokenPrivileges, ptrOffset, false);
                ptrOffset = IntPtr.Add(ptrOffset, Marshal.SizeOf(tokenPrivileges));

                for (int i = 1; i < privileges.Length; i++)
                {
                    NativeHelpers.LUID_AND_ATTRIBUTES luidAttr = new NativeHelpers.LUID_AND_ATTRIBUTES()
                    {
                        Attributes = PrivilegeAttributes.Enabled,
                        Luid = LookupPrivilegeValue(privileges[i]),
                    };
                    Marshal.StructureToPtr(luidAttr, ptrOffset, false);
                    ptrOffset = IntPtr.Add(ptrOffset, Marshal.SizeOf(luidAttr));
                }

                if (!NativeMethods.ImpersonateSelf(SecurityImpersonationLevel.SecurityImpersonation))
                    throw new Win32Exception("ImpersonateSelf() failed");
                try
                {
                    IntPtr currentProcess = NativeMethods.GetCurrentProcess();
                    SafeNativeHandle token;
                    if (!NativeMethods.OpenProcessToken(currentProcess, TokenAccessLevels.AdjustPrivileges, out token))
                        throw new Win32Exception("OpenProcessToken() failed");

                    using (token)
                    {
                        UInt32 returnLength;
                        bool res = NativeMethods.AdjustTokenPrivileges(token.DangerousGetHandle(), false,
                            buffer.DangerousGetHandle(), 0, IntPtr.Zero, out returnLength);
                        int lastError = Marshal.GetLastWin32Error();

                        if (!res || lastError == 0x00000514)  // ERROR_NOT_ALL_ASSIGNED
                            throw new Win32Exception(lastError, "AdjustTokenPrivileges() failed");
                    }
                }
                catch
                {
                    NativeMethods.RevertToSelf();
                    throw;
                }
            }
        }

        private NativeHelpers.LUID LookupPrivilegeValue(string privilege)
        {
            NativeHelpers.LUID luid = new NativeHelpers.LUID();
            if (!NativeMethods.LookupPrivilegeValueW(null, privilege, ref luid))
                throw new Win32Exception(String.Format("LookupPrivilegeValueW({0}) failed", privilege));

            return luid;
        }

        public void Dispose()
        {
            NativeMethods.RevertToSelf();
            GC.SuppressFinalize(this);
        }
        ~PrivilegeEnabler() { this.Dispose(); }
    }

    public class SecurityBuffer
    {
        public BufferType BufferType;
        public byte[] Data;
    }

    public class SecurityPackageInfo
    {
        public Int32 Capabilities;
        public Int16 Version;
        public Int16 RPCID;
        public Int32 MaxToken;
        public string Name;
        public string Comment;
    }

    public class UserImpersonation : IDisposable
    {
        public UserImpersonation(IdentityReference account)
        {
            TokenAccessLevels tokenAccess = TokenAccessLevels.Duplicate | TokenAccessLevels.Impersonate |
                TokenAccessLevels.Query;

            foreach (Process process in Process.GetProcesses())
            {
                using (SafeNativeHandle processHandle = NativeMethods.OpenProcess(ProcessAccessFlags.QueryInformation, false,
                    (UInt32)process.Id))
                {
                    if (processHandle.IsInvalid)
                        continue;

                    SafeNativeHandle token;

                    if (!NativeMethods.OpenProcessToken(processHandle.DangerousGetHandle(), tokenAccess, out token))
                        continue;

                    using (token)
                    using (SafeMemoryBuffer tokenUser = GetTokenInformation(token,
                        NativeHelpers.TokenInformationClass.TokenUser))
                    {
                        NativeHelpers.TOKEN_USER user = (NativeHelpers.TOKEN_USER)Marshal.PtrToStructure(
                            tokenUser.DangerousGetHandle(), typeof(NativeHelpers.TOKEN_USER));

                        SecurityIdentifier actualUser = new SecurityIdentifier(user.User.Sid);
                        if (!actualUser.Equals(account.Translate(typeof(SecurityIdentifier))))
                            continue;

                        if (!NativeMethods.ImpersonateLoggedOnUser(token.DangerousGetHandle()))
                            continue;

                        return;
                    }
                }
            }

            throw new Exception(String.Format("Failed to get access to a token for {0}", account.ToString()));
        }

        private SafeMemoryBuffer GetTokenInformation(SafeHandle handle, NativeHelpers.TokenInformationClass infoClass)
        {
            UInt32 bufferLength;
            NativeMethods.GetTokenInformation(handle.DangerousGetHandle(), infoClass,
                new SafeMemoryBuffer(IntPtr.Zero), 0, out bufferLength);

            SafeMemoryBuffer buffer = new SafeMemoryBuffer((int)bufferLength);
            if (!NativeMethods.GetTokenInformation(handle.DangerousGetHandle(), infoClass, buffer, bufferLength,
                out bufferLength))
            {
                throw new Win32Exception(String.Format("GetTokenInformation({0}) failed", infoClass.ToString()));
            }

            return buffer;
        }

        public void Dispose()
        {
            NativeMethods.RevertToSelf();
            GC.SuppressFinalize(this);
        }
        ~UserImpersonation() { this.Dispose(); }
    }

    [Flags]
    public enum BufferType : uint
    {
        Empty = 0x0000000,
        Data = 0x00000001,
        Token = 0x00000002,
        PkgParams = 0x00000003,
        Missing = 0x00000004,
        Extra = 0x00000005,
        StreamTrailer = 0x00000006,
        StreamHeader = 0x00000007,
        NegotiationInfo = 0x00000008,
        Padding = 0x00000009,
        Stream = 0x0000000A,
        MechList = 0x0000000B,
        MechlistSignature = 0x0000000C,
        Target = 0x0000000D,
        ChannelBindings = 0x0000000E,
        ChangePassResponse = 0x0000000F,
        TargetHost = 0x00000010,
        Alert = 0x00000011,
        ApplicationProtocols = 0x00000012,
        StrpProtectionProfiles = 0x00000013,
        StrpMasterKeyIdentifier = 0x00000014,
        TokenBinding = 0x00000015,
        PreSharedKey = 0x00000016,
        PreSharedKeyIdentity = 0x00000017,
        DtlsMtu = 0x00000018,
        ReadOnlyWithChecksum = 0x10000000,
        ReadOnly = 0x80000000,
        AttrMask = 0xF0000000,
    }

    [Flags]
    public enum PrivilegeAttributes : uint
    {
        Disabled = 0x00000000,
        EnabledByDefault = 0x00000001,
        Enabled = 0x00000002,
        Removed = 0x00000004,
        UsedForAccess = 0x80000000,
    }

    [Flags]
    public enum ProcessAccessFlags : uint
    {
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VmOperation = 0x00000008,
        VmRead = 0x00000010,
        VmWrite = 0x00000020,
        DupHandle = 0x00000040,
        CreateProcess = 0x00000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        SuspendResume = 0x00000800,
        QueryLimitedInformation = 0x00001000,
        Delete = 0x00010000,
        ReadControl = 0x00020000,
        WriteDac = 0x00040000,
        WriteOwner = 0x00080000,
        Synchronize = 0x00100000,
    }

    public enum SecPackageAttribute : uint
    {
        ServerAuthFlags = 0x80000083,
        AccessToken = 0x80000012,
        Creds = 0x80000080,
        NegotiationPackage = 0x80000081,
        FullAccessToken = 0x80000082,
        CertTrustStatus = 0x80000084,
        Creds2 = 0x80000086,
        Sizes = 0x00000000,
        PackageInfo = 0x0000000A,
        SubjectSecurityAttributes = 0x0000007C,
    }

    public enum SecurityImpersonationLevel : uint
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3,
    }
}

namespace SSPI
{
    class Program
    {
        static void Main(string[] args)
        {
            using (new Pyspnego.PrivilegeEnabler("SeDebugPrivilege"))
            using (new Pyspnego.UserImpersonation(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)))
            {
                IPAddress localhost = new IPAddress(0);
                IPEndPoint localEndpoint = new IPEndPoint(localhost, 16854);
                Socket listener = new Socket(localhost.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                listener.Bind(localEndpoint);
                listener.Listen(1);

                Socket handler = listener.Accept();

                string package = Encoding.UTF8.GetString(ReceiveData(handler));

                using (Pyspnego.ServerCredential credential = new Pyspnego.ServerCredential(package))
                using (Pyspnego.SecurityContext context = new Pyspnego.SecurityContext(credential))
                {
                    while (!context.Complete)
                    {
                        byte[] data = ReceiveData(handler);
                        if (data.Length == 0)
                            return;

                        byte[] response = context.Step(data);

                        handler.Send(BitConverter.GetBytes(response.Length));
                        if (response.Length > 0)
                            handler.Send(response);
                    }

                    byte[] encryptedData = ReceiveData(handler);
                    byte[] decryptedData = context.Unwrap(encryptedData);

                    byte[] encryptedMessage = context.Wrap(decryptedData);

                    handler.Send(BitConverter.GetBytes(encryptedMessage.Length));
                    handler.Send(encryptedMessage);

                    handler.Shutdown(SocketShutdown.Both);
                    handler.Close();
                }
            }
        }

        private static byte[] ReceiveData(Socket socket)
        {
            byte[] data = new byte[4];
            socket.Receive(data);

            data = new byte[BitConverter.ToInt32(data, 0)];
            socket.Receive(data, data.Length, SocketFlags.None);

            return data;
        }
    }
}
