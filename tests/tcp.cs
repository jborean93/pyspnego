using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Text;


namespace Authentication
{
    public class NativeHelpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct CREDSSP_CRED
        {
            public CredSubmitType Type;
            public IntPtr pSchannelCred;
            public IntPtr pSpnegoCred;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
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
            public UInt32 cbBuffer;
            public BufferType BufferType;
            public IntPtr pvBuffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SecHandle
        {
            public UIntPtr dwLower;
            public UIntPtr dwUpper;
        }
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

    internal class SafeContextBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        [DllImport("Secure32.dll")]
        private static extern UInt32 FreeContextBuffer(
            IntPtr pvContextBuffer);

        protected SafeContextBuffer() : base(true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            FreeContextBuffer(this.handle);
            return true;
        }
    }

    public class SafeCredential : SafeHandleZeroOrMinusOneIsInvalid
    {
        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        private static extern UInt32 AcquireCredentialsHandleW(
            [MarshalAs(UnmanagedType.LPWStr)] string pszPrincipal,
            [MarshalAs(UnmanagedType.LPWStr)] string pPackage,
            CredentialUse fCredentialUse,
            IntPtr pvLogonId,
            IntPtr pAuthData,
            IntPtr pGetKeyFn,
            IntPtr pvGetKeyArgument,
            IntPtr phCredential,
            out Int64 ptsExpiry);

        [DllImport("Secur32.dll")]
        private static extern UInt32 FreeCredentialsHandle(
            IntPtr phCredential);

        private bool Initialized = false;

        public Int64 Expiry;

        public SafeCredential(string principal, string package, CredentialUse use, object authData) : base(true)
        {
            base.SetHandle(Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeHelpers.SecHandle))));

            SafeMemoryBuffer authBuffer;
            if (authData != null)
            {
                authBuffer = new SafeMemoryBuffer(Marshal.SizeOf(authData));
                Marshal.PtrToStructure(authBuffer.DangerousGetHandle(), authData);
            }
            else
                authBuffer = new SafeMemoryBuffer(IntPtr.Zero);

            using (authBuffer)
            {
                UInt32 res = AcquireCredentialsHandleW(principal, package, use, IntPtr.Zero,
                    authBuffer.DangerousGetHandle(), IntPtr.Zero, IntPtr.Zero, this.handle, out Expiry);

                if (res != 0)
                    throw new Exception(res.ToString());
            }

            Initialized = true;
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            if (Initialized)
                FreeCredentialsHandle(this.handle);

            Marshal.FreeHGlobal(this.handle);

            return true;
        }
    }

    public class SafeSecurityContext : SafeHandleZeroOrMinusOneIsInvalid
    {
        [DllImport("Secur32.dll")]
        private static extern UInt32 AcceptSecurityContext(
            SafeCredential phCredential,
            IntPtr phContext,
            ref NativeHelpers.SecBufferDesc pInput,
            ContextRequirements fContextReq,
            DataRepresentation TargetDataRep,
            IntPtr phNewContext,
            ref NativeHelpers.SecBufferDesc pOutput,
            out ContextRequirements pfContextAttr,
            out Int64 ptsExpiry);

        [DllImport("Secur32.dll")]
        private static extern UInt32 DeleteSecurityContext(
            IntPtr phContext);

        private SafeCredential credential;
        private bool initialized = false;
        private UInt32 SECBUFFER_VERSION = 0;

        public bool Complete = false;
        public ContextRequirements ContextAttributes;
        public Int64 Expiry;

        public SafeSecurityContext(SafeCredential credential) : base(true)
        {
            this.credential = credential;
            base.SetHandle(Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeHelpers.SecHandle))));
        }

        public List<SecurityBuffer> Step(List<SecurityBuffer> input)
        {
            IntPtr contextPtr = initialized ? this.handle : IntPtr.Zero;

            int bufferLength = Marshal.SizeOf(typeof(NativeHelpers.SecBuffer));
            int bufferDataLength = input.Sum(i => i.Data.Length);

            using (SafeMemoryBuffer inputBuffer = new SafeMemoryBuffer(
                (bufferLength * input.Count) + bufferDataLength))
            {
                IntPtr inputBufferPtr = inputBuffer.DangerousGetHandle();
                IntPtr inputBufferDataPtr = IntPtr.Add(inputBufferPtr, bufferLength * input.Count);

                NativeHelpers.SecBufferDesc bufferDesc = new NativeHelpers.SecBufferDesc()
                {
                    ulVersion = 0,
                    cBuffers = (UInt32)input.Count,
                    pBuffers = inputBufferPtr,
                };

                foreach (SecurityBuffer buffer in input)
                {
                    NativeHelpers.SecBuffer bufferElement = new NativeHelpers.SecBuffer()
                    {
                        BufferType = buffer.BufferType,
                        cbBuffer = (UInt32)buffer.Data.Length,
                        pvBuffer = inputBufferDataPtr,
                    };
                    Marshal.Copy(buffer.Data, 0, inputBufferDataPtr, buffer.Data.Length);
                    IntPtr.Add(inputBufferDataPtr, buffer.Data.Length);

                    Marshal.StructureToPtr(bufferElement, inputBufferPtr, false);
                    inputBufferPtr = IntPtr.Add(inputBufferPtr, bufferLength);
                }

                int bufferSize = 48000;
                while (true)
                {
                    using (SafeMemoryBuffer outputTokenPtr = new SafeMemoryBuffer(bufferLength + bufferSize))
                    {
                        NativeHelpers.SecBufferDesc outputBuffer = new NativeHelpers.SecBufferDesc()
                        {
                            ulVersion = 0,
                            cBuffers = (UInt32)1,
                            pBuffers = outputTokenPtr.DangerousGetHandle(),
                        };

                        NativeHelpers.SecBuffer outputToken = new NativeHelpers.SecBuffer()
                        {
                            BufferType = BufferType.Token,
                            cbBuffer = (UInt32)bufferSize,
                            pvBuffer = IntPtr.Add(outputTokenPtr.DangerousGetHandle(), bufferLength),
                        };
                        Marshal.StructureToPtr(outputToken, outputTokenPtr.DangerousGetHandle(), false);

                        UInt32 res = AcceptSecurityContext(
                            credential,
                            contextPtr,
                            ref bufferDesc,
                            ContextRequirements.AllocateMemory,
                            DataRepresentation.Native,
                            this.handle,
                            ref outputBuffer,
                            out ContextAttributes,
                            out Expiry);
                        initialized = true;

                        if (res == 2148074273)  // SEC_E_BUFFER_TOO_SMALL
                        {
                            bufferSize++;
                            continue;
                        }
                        else if (res == 0)
                            Complete = true;
                        else if (!new List<UInt32>() { 0x00090314, 0x00090313, 0x00090312 }.Contains(res))
                            throw new Exception(String.Format("AcceptSecurityContext() failed {0} - 0x{0:X8}", res));

                        IntPtr outputBufferPtr = outputBuffer.pBuffers;
                        List<SecurityBuffer> output = new List<SecurityBuffer>();
                        for (int i = 0; i < outputBuffer.cBuffers; i++)
                        {
                            NativeHelpers.SecBuffer outBuffer = (NativeHelpers.SecBuffer)Marshal.PtrToStructure(
                                outputBufferPtr, typeof(NativeHelpers.SecBuffer));

                            SecurityBuffer a = new SecurityBuffer()
                            {
                                BufferType = outBuffer.BufferType,
                                Data = new byte[outBuffer.cbBuffer],
                            };
                            if (outBuffer.cbBuffer > 0)
                            {
                                Marshal.Copy(outBuffer.pvBuffer, a.Data, 0, a.Data.Length);
                            }

                            output.Add(a);
                            outputBufferPtr = IntPtr.Add(outputBufferPtr, bufferLength);
                        }

                        return output;
                    }
                }
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            if (initialized)
                DeleteSecurityContext(this.handle);

            Marshal.FreeHGlobal(this.handle);

            return true;
        }
    }

    public class SecurityBuffer
    {
        public BufferType BufferType;
        public byte[] Data;
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
    public enum ContextRequirements : uint
    {
        Delegate = 0x00000001,
        MutualAuth = 0x00000002,
        ReplayDetect = 0x00000004,
        SequenceDetect = 0x00000008,
        Confidentiality = 0x00000010,
        UseSessionKey = 0x00000020,
        SessionTicket = 0x00000040,
        AllocateMemory = 0x00000100,
        UseDceStyle = 0x00000200,
        Datagram = 0x00000400,
        Connection = 0x00000800,
        CallLevel = 0x00001000,
        FragmentSupplied = 0x00002000,
        ExtendedError = 0x00008000,
        Stream = 0x00010000,
        Integrity = 0x00020000,
        Licensing = 0x00040000,
        Identify = 0x00080000,
        AllowNullSession = 0x00100000,
        AllowNonUserLogons = 0x00200000,
        AllowContextReplay = 0x00400000,
        FragmentToFit = 0x00800000,
        NoToken = 0x01000000,
        ProxyBindings = 0x04000000,
        Reauthentication = 0x08000000,
        AllowMissingBindings = 0x10000000,
    }

    public enum CredSubmitType : uint
    {
        PasswordCreds = 2,
        SchannelCreds = 4,
        CertificateCreds = 13,
        SubmitBufferBoth = 50,
        SubmitBufferBothOld = 51,
        CredEx = 100,
    }

    public enum CredentialUse : uint
    {
        Inbound = 0x00000001,
        Outbound = 0x00000002,
        Both = 0x00000003,
        Default = 0x00000004,
    }

    public enum DataRepresentation : uint
    {
        Network = 0x00000000,
        Native = 0x00000010,
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

            string package = Encoding.ASCII.GetString(ReceiveData(handler));
            using (Authentication.SafeCredential credential = new Authentication.SafeCredential(null, package,
                Authentication.CredentialUse.Inbound, null))
            using (Authentication.SafeSecurityContext context = new Authentication.SafeSecurityContext(credential))
            {
                while (!context.Complete)
                {
                    byte[] data = ReceiveData(handler);

                    List<Authentication.SecurityBuffer> inputBuffers = new List<Authentication.SecurityBuffer>()
                    {
                        new Authentication.SecurityBuffer()
                        {
                            BufferType = Authentication.BufferType.Token,
                            Data = data,
                        },
                    };

                    Authentication.SecurityBuffer response = context.Step(inputBuffers)[0];

                    handler.Send(BitConverter.GetBytes(response.Data.Length));
                    if (response.Data.Length > 0)
                        handler.Send(response.Data);
                }

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
