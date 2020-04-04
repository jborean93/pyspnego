using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;


namespace Authentication
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
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SecBufferDesc
        {
            public UInt32 ulVersion;
            public UInt32 cBuffers;
            public IntPtr pBuffers;
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
            TokenPrivileges = 3,
            TokenStatistics = 10,
            TokenElevationType = 18,
            TokenLinkedToken = 19,
        }
    }

    internal class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(
            IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern SafeNativeHandle GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            SafeNativeHandle TokenHandle,
            NativeHelpers.TokenInformationClass TokenInformationClass,
            SafeMemoryBuffer TokenInformation,
            UInt32 TokenInformationLength,
            out UInt32 ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            SafeNativeHandle hToken);

        [DllImport("Advapi32.dll")]
        public static extern bool ImpersonateSelf(
            SecurityImpersonationLevel ImpersonationLevel);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupPrivilegeNameW(
            string lpSystemName,
            ref NativeHelpers.LUID lpLuid,
            StringBuilder lpName,
            ref UInt32 cchName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SafeNativeHandle OpenProcess(
            ProcessAccessFlags dwDesiredAccess,
            bool bInheritHandle,
            UInt32 dwProcessId);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            SafeNativeHandle ProcessHandle,
            TokenAccessLevels DesiredAccess,
            out SafeNativeHandle TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();






        [DllImport("Secur32.dll")]
        public static extern UInt32 AcceptSecurityContext(
            ServerCredential phCredential,
            IntPtr phContext,
            ref NativeHelpers.SecBufferDesc pInput,
            UInt32 fContextReq,
            UInt32 TargetDataRep,
            IntPtr phNewContext,
            ref NativeHelpers.SecBufferDesc pOutput,
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

        [DllImport("Secur32.dll")]
        public static extern UInt32 CompleteAuthToken(
            IntPtr phContext,
            ref NativeHelpers.SecBufferDesc pToken);

        [DllImport("Secur32.dll")]
        public static extern UInt32 DecryptMessage(
            IntPtr phContext,
            ref NativeHelpers.SecBufferDesc pMessage,
            UInt32 MessageSeqNo,
            ref UInt32 pfQOP);

        [DllImport("Secur32.dll")]
        public static extern UInt32 DeleteSecurityContext(
            IntPtr phContext);

        [DllImport("Secur32.dll")]
        public static extern UInt32 FreeContextBuffer(
            IntPtr pvContextBuffer);

        [DllImport("Secur32.dll")]
        public static extern UInt32 FreeCredentialsHandle(
            IntPtr phCredential);

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        public static extern UInt32 QuerySecurityPackageInfoW(
            string pPackageName,
            ref IntPtr ppPackageInfo);
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

    public class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeNativeHandle() : base(true) { }
        public SafeNativeHandle(IntPtr handle) : base(true) { this.handle = handle; }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(handle);
        }
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

        public bool Complete = false;
        public UInt32 ContextAttributes;
        public Int64 Expiry;

        public SecurityContext(ServerCredential credential) : base(true)
        {
            this._credential = credential;
            base.SetHandle(Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeHelpers.SecHandle))));
        }

        public SecurityBuffer Step(List<SecurityBuffer> input)
        {
            IntPtr contextPtr = _initialized ? this.handle : IntPtr.Zero;
            int maxTokenSize = _credential.PackageInfo.MaxToken;
            int bufferLength = Marshal.SizeOf(typeof(NativeHelpers.SecBuffer));

            using (SafeMemoryBuffer inputBufferPtr = CreateSecBufferArray(input))
            using (SafeMemoryBuffer outputBufferPtr = new SafeMemoryBuffer(bufferLength + maxTokenSize))
            {
                NativeHelpers.SecBufferDesc inputBuffer = new NativeHelpers.SecBufferDesc()
                {
                    cBuffers = (UInt32)input.Count,
                    pBuffers = inputBufferPtr.DangerousGetHandle(),
                };

                NativeHelpers.SecBufferDesc outputBuffer = new NativeHelpers.SecBufferDesc()
                {
                    cBuffers = 1,
                    pBuffers = outputBufferPtr.DangerousGetHandle(),
                };

                NativeHelpers.SecBuffer outputToken = new NativeHelpers.SecBuffer()
                {
                    BufferType = BufferType.Token,
                    cbBuffer = maxTokenSize,
                    pvBuffer = IntPtr.Add(outputBuffer.pBuffers, bufferLength),
                };
                Marshal.StructureToPtr(outputToken, outputBuffer.pBuffers, false);

                UInt32 res = NativeMethods.AcceptSecurityContext(
                    _credential,
                    contextPtr,
                    ref inputBuffer,
                    0,
                    0x00000010,  // SECURITY_NATIVE_DREP
                    this.handle,
                    ref outputBuffer,
                    out ContextAttributes,
                    out Expiry);

                _initialized = true;
                Complete = res == SEC_E_OK || res == SEC_I_COMPLETE_NEEDED;

                if (new List<UInt32>() { SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED }.Contains(res))
                    res = NativeMethods.CompleteAuthToken(this.handle, ref outputBuffer);

                if (!new List<UInt32>() { SEC_E_OK, SEC_I_CONTINUE_NEEDED }.Contains(res))
                    throw new Exception(String.Format("AcceptSecurityContext() failed {0} - 0x{0:X8}", res));

                outputToken = (NativeHelpers.SecBuffer)Marshal.PtrToStructure(outputBuffer.pBuffers,
                    typeof(NativeHelpers.SecBuffer));
                SecurityBuffer output = new SecurityBuffer()
                {
                    BufferType = outputToken.BufferType,
                    Data = new byte[outputToken.cbBuffer],
                };
                Marshal.Copy(outputToken.pvBuffer, output.Data, 0, output.Data.Length);

                return output;
            }
        }

        public byte[] Unwrap(byte[] data)
        {
            int bufferLength = Marshal.SizeOf(typeof(NativeHelpers.SecBuffer));

            using (SafeMemoryBuffer buffer = new SafeMemoryBuffer((bufferLength * 2) + data.Length))
            {
                NativeHelpers.SecBufferDesc inputInfo = new NativeHelpers.SecBufferDesc()
                {
                    cBuffers = 2,
                    pBuffers = buffer.DangerousGetHandle(),
                };

                NativeHelpers.SecBuffer streamBuffer = new NativeHelpers.SecBuffer()
                {
                    BufferType = BufferType.Stream,
                    cbBuffer = data.Length,
                    pvBuffer = IntPtr.Add(inputInfo.pBuffers, bufferLength * 2),
                };
                Marshal.Copy(data, 0, streamBuffer.pvBuffer, data.Length);
                Marshal.StructureToPtr(streamBuffer, inputInfo.pBuffers, false);

                NativeHelpers.SecBuffer dataBuffer = new NativeHelpers.SecBuffer()
                {
                    BufferType = BufferType.Data,
                    cbBuffer = 0,
                    pvBuffer = IntPtr.Zero,
                };
                IntPtr dataBufferPtr = IntPtr.Add(inputInfo.pBuffers, bufferLength);
                Marshal.StructureToPtr(dataBuffer, dataBufferPtr, false);

                UInt32 qop = 0;
                UInt32 res = NativeMethods.DecryptMessage(this.handle, ref inputInfo, 0, ref qop);
                if (res != SEC_E_OK)
                    throw new Exception(String.Format("DecryptMessage() failed {0} - 0x{0:X8}", res));

                dataBuffer = (NativeHelpers.SecBuffer)Marshal.PtrToStructure(dataBufferPtr,
                    typeof(NativeHelpers.SecBuffer));

                byte[] decryptedData = new byte[dataBuffer.cbBuffer];
                Marshal.Copy(dataBuffer.pvBuffer, decryptedData, 0, decryptedData.Length);

                return decryptedData;
            }
        }

        private static SafeMemoryBuffer CreateSecBufferArray(List<SecurityBuffer> buffers)
        {
            int bufferLength = Marshal.SizeOf(typeof(NativeHelpers.SecBuffer));
            int bufferDataLength = buffers.Sum(i => i.Data.Length);
            int bufferDataOffset = bufferLength * buffers.Count;

            SafeMemoryBuffer securityBuffer = new SafeMemoryBuffer(bufferDataOffset + bufferDataLength);

            IntPtr inputBufferPtr = securityBuffer.DangerousGetHandle();
            IntPtr inputBufferDataPtr = IntPtr.Add(inputBufferPtr, bufferDataOffset);

            foreach (SecurityBuffer buffer in buffers)
            {
                NativeHelpers.SecBuffer bufferElement = new NativeHelpers.SecBuffer()
                {
                    BufferType = buffer.BufferType,
                    cbBuffer = buffer.Data.Length,
                    pvBuffer = inputBufferDataPtr,
                };
                Marshal.Copy(buffer.Data, 0, inputBufferDataPtr, buffer.Data.Length);
                IntPtr.Add(inputBufferDataPtr, buffer.Data.Length);

                Marshal.StructureToPtr(bufferElement, inputBufferPtr, false);
                inputBufferPtr = IntPtr.Add(inputBufferPtr, bufferLength);
            }

            return securityBuffer;
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
        public PrivilegeEnabler(List<string> privileges)
        {

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

    public enum SecurityImpersonationLevel : uint
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3,
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
}

namespace SSPI
{
    class Program
    {
        static void Main(string[] args)
        {
            IPAddress localhost = new IPAddress(0);
            IPEndPoint localEndpoint = new IPEndPoint(localhost, 16854);
            Socket listener = new Socket(localhost.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(localEndpoint);
            listener.Listen(1);

            Socket handler = listener.Accept();

            string package = Encoding.UTF8.GetString(ReceiveData(handler));

            using (Authentication.ServerCredential credential = new Authentication.ServerCredential(package))
            using (Authentication.SecurityContext context = new Authentication.SecurityContext(credential))
            {
                while (!context.Complete)
                {
                    byte[] data = ReceiveData(handler);
                    if (data.Length == 0)
                        return;

                    List<Authentication.SecurityBuffer> inputBuffers = new List<Authentication.SecurityBuffer>()
                    {
                        new Authentication.SecurityBuffer()
                        {
                            BufferType = Authentication.BufferType.Token,
                            Data = data,
                        },
                    };

                    Authentication.SecurityBuffer response = context.Step(inputBuffers);

                    handler.Send(BitConverter.GetBytes(response.Data.Length));
                    if (response.Data.Length > 0)
                        handler.Send(response.Data);
                }

                byte[] encryptedData = ReceiveData(handler);
                byte[] decryptedData = context.Unwrap(encryptedData);

                handler.Send(BitConverter.GetBytes(decryptedData.Length));
                handler.Send(decryptedData);

                handler.Shutdown(SocketShutdown.Both);
                handler.Close();
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
