using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Net;
using System.Runtime;
namespace IPSecDotNet5
{
    class NativeMethods
    {
        public class Polstructs
        {

            
            public static int IPSEC_REGISTRY_PROVIDER = 0;
            public static int IPSEC_DIRECTORY_PROVIDER = 1;
            public static int IPSEC_FILE_PROVIDER = 2;

            public struct IPSEC_POLICY_DATA
            {
                public Guid PolicyIdentifier;
                public int dwPollingInterval;
                public IntPtr pIpsecISAKMPData;
                public IntPtr ppIpsecNFAData;
                public int dwNumNFACount;
                public int dwWhenChanged;
                [MarshalAs(UnmanagedType.LPWStr)] public string pszIpsecName;
                [MarshalAs(UnmanagedType.LPWStr)] public string pszDescription;
                public Guid ISAKMPIdentifier;
            }
            
            public struct IPSEC_ISAKMP_DATA
            {
                public Guid ISAKMPIdentifier;
                public Oakdefs.ISAKMP_POLICY ISAKMPPolicy;
                public int dwNumISAKMPSecurityMethods;
                public IntPtr pSecurityMethods; //PCRYPTO_BUNDLE
                public int dwWhenChanged;
            }
        
            public struct IPSEC_FILTER_DATA
            {
                public Guid FilterIdentifier;
                public int dwNumFilterSpecs;
                //A pointer to an unmanaged block of memory containing pointers to IPSEC_FILTER_SPEC structs.
                public IntPtr ppFilterSpecs;
                public int dwWhenChanged;
                [MarshalAs(UnmanagedType.LPWStr)] public string pszIpsecName;
                [MarshalAs(UnmanagedType.LPWStr)] public string pszIpsecDescription;
            }

            public struct IPSEC_NEGPOL_DATA
            {
                public Guid NegPolIdentifier;
                public Guid NegPolAction;
                public Guid NegPolType;
                public int dwSecurityMethodCount;
                public IntPtr pIpsecSecurityMethods; //IPSEC_SECURITY_METHOD *
                public int dwWhenChanged;
                [MarshalAs(UnmanagedType.LPWStr)] public string pszIpsecName;
                [MarshalAs(UnmanagedType.LPWStr)] public string pszDescription;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IPSEC_FILTER_SPEC
            {
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.LPWStr)] public string pszSrcDNSName;
                [FieldOffset(8)]
                [MarshalAs(UnmanagedType.LPWStr)] public string pszDestDNSName;
                [FieldOffset(16)]
                [MarshalAs(UnmanagedType.LPWStr)] public string pszDescription;
                [FieldOffset(24)]
                public Guid FilterSpecGUID;
                [FieldOffset(40)]
                public int dwMirrorFlag;
                [FieldOffset(44)]
                public int unknownFlag4; //Needs to be set to 4 when using IPv4 Address.
                [FieldOffset(48)]
                public int unknownFlag1; //Needs to be set to 1 when using IPv4 Subnet.
                [FieldOffset(52)]
                public Ipsec.IPSEC_FILTER filter; //IPSEC_FILTER -- missing definition.
                
            }

            public struct IPSEC_NFA_DATA
            {
                [MarshalAs(UnmanagedType.LPWStr)] public string pszIpsecName;
                public Guid NFAIdentifier;
                public int dwAuthMethodCount;
                public IntPtr ppAuthMethods; //PIPSEC_AUTH_METHOD *
                public int dwInterfaceType;
                [MarshalAs(UnmanagedType.LPWStr)] public string pszInterfaceName;
                public int dwTunnelIpAddr;
                public int dwTunnelFlags;
                public int dwActiveFlag;
                [MarshalAs(UnmanagedType.LPWStr)] public string pszEndPointName;
                public IntPtr pIpsecFilterData; //PIPSEC_FILTER_DATA
                public IntPtr pIpsecNegPolData; //PIPSEC_NEGPOL_DATA
                public int dwWhenChanged;
                public Guid NegPolIdentifier;
                public Guid FilterIdentifier;
            }
        }
        public class Polstore2 : Polstructs
        {
            public static readonly Guid GUID_NEGOTIATION_ACTION_BLOCK = new("3f91a819-7647-11d1-864d-d46a00000000");
            public static readonly Guid GUID_NEGOTATION_TYPE_STANDARD = new("62f49e10-6c37-11d1-864c-14a300000000");
            /// <summary>
            /// 
            /// </summary>
            /// <param name="pszMachineName"></param>
            /// <param name="dwTypeOfStore"></param>
            /// <param name="pszFileName"></param>
            /// <param name="phPolicyStore"></param>
            /// <returns></returns>
            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecOpenPolicyStore([MarshalAs(UnmanagedType.LPWStr)] string pszMachineName, int dwTypeOfStore, [MarshalAs(UnmanagedType.LPWStr)] string pszFileName, out IntPtr phPolicyStore);

            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecClosePolicyStore(IntPtr hPolicyStore);
            #region IPSecGet
            /// <summary>
            /// 
            /// </summary>
            /// <param name="hStore"></param>
            /// <param name="pipspd"></param>
            /// <returns></returns>
            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecGetAssignedPolicyData(IntPtr hStore, out IntPtr pipspd);
            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecGetISAKMPData(IntPtr hPolicyStore, Guid ISAKMPGUID, IntPtr ppIpsecISAKMPData);

            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecGetFilterData(IntPtr hPolicyStore, Guid FilterGUID, IntPtr ppIpsecFilterData);

            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecGetNegPolData(IntPtr hPolicyStore, Guid NegPolGuid, IntPtr ppIpsecNegPolData);
            #endregion
            #region IPSecAssign
            /// <summary>
            /// 
            /// </summary>
            /// <param name="hPolicyStore"></param>
            /// <param name="PolicyGuid"></param>
            /// <returns></returns>
            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecUnassignPolicy(IntPtr hPolicyStore, Guid PolicyGuid);
            /// <summary>
            /// 
            /// </summary>
            /// <param name="hPolicyStore"></param>
            /// <param name="PolicyGuid"></param>
            /// <returns></returns>
            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecAssignPolicy(IntPtr hPolicyStore, Guid PolicyGuid);

            #endregion
            #region IPSecCreate
            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecCreateFilterData(IntPtr hPolicyStore, IntPtr pIpsecFilterData);

            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecCreateISAKMPData(IntPtr hPolicyStore, IntPtr pIpsecISAKMPData);

            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecCreateNegPolData(IntPtr hPolicyStore, IntPtr pIpsecNegPolData);

            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecCreatePolicyData(IntPtr hPolicyStore, IntPtr pIpsecPolicyData);
            #endregion

        }
        public static class Ipsec
        {
            [StructLayout(LayoutKind.Explicit)]
            public struct IPSEC_FILTER
            {
                [FieldOffset(0)]
                public uint SrcAddr;
                [FieldOffset(15)]
                public uint SrcMask;
                [FieldOffset(40)]
                public uint DstAddr;
                [FieldOffset(55)]
                public uint DstMask;
                [FieldOffset(44)] //Unknown
                public uint TunnelAddr;
                [FieldOffset(88)]
                public uint Protocol; //-- 0x6 = TCP, 0x11 = UDP
                [FieldOffset(72)]
                public uint SrcUnknownFlag1; //Potentially a counter. Set to 1 if declaring SrcPort.
                [FieldOffset(76)]
                public uint SrcPort;
                [FieldOffset(80)]
                public uint DstUnknownFlag1; //Potentially a counter. Set to 1 if declaring DstPort.
                [FieldOffset(84)]
                public uint DstPort;
                [FieldOffset(89)] //Unknown
                public bool TunnelFilter;
                [FieldOffset(90)] //Unknown
                public char Pad;
                [FieldOffset(91)] //Unknown
                public ushort Flags;
            }

        }
        public static class Oakdefs
        {
            public struct OAKLEY_ALGORITHM
            {
                public uint AlgorithmIdentifier;
                public uint KeySize;
                public uint Rounds;
            }
            public struct OAKLEY_LIFETIME
            {
                public int KBytes;
                public int Seconds;
            }
            public struct CRYPTO_BUNDLE
            {
                public byte MajorVersion;
                public byte MinorVersion;
                public OAKLEY_ALGORITHM EncryptionAlgorithm;
                public OAKLEY_ALGORITHM HashAlgorithm;
                public OAKLEY_ALGORITHM PseudoRandomFunction;  //unused
                public byte AuthenticationMethod;
                public int OakleyGroup;
                public int QuickModeLimit;
                public OAKLEY_LIFETIME Lifetime;
                public bool PfsIdentityRequired;
            }
            public struct ISAKMP_POLICY
            {
                public Guid PolicyId;
                public bool IdentityProtectionRequired;
                public bool PfsIdentityRequired;
                public int ThreadingFactor;
                public int AquireLimit;
                public int ReceiveLimit;
                public int AquireSize;
                public int ReceiveSize;
                public int RepearInterval;
                public int RpcMaxCalls;
                public int RetryInterval;
                public int RetryLimit;
            }
        }
        //Justify?
        public static class Winipsec
        {
            enum IPSEC_OPERATION
            {
                NONE = 0,
                AUTHENTICATION,
                ENCRYPTION,
                COMPRESSION,
                SA_DELETE
            }
            enum HMAC_AH_ALGO
            {
                HMAC_AH_NONE = 0,
                HMAC_AH_MD5,
                HMAC_AH_SHA1,
                HMAC_AH_MAX
            }
            struct KEY_LIFETIME
            {
                int uKeyExpirationTime;
                int uKeyExpirationKBytes;
            }
            struct IPSEC_QM_ALGO
            {
                IPSEC_OPERATION Operation;
                int uAlgoIdentifier;
                HMAC_AH_ALGO uSecAlgoIdentifier;
                int uAlgoKeyLen;
                int uSecAlgoKeyLen;
                int uAlgoRounds;
                int MySpi; //IPSEC_QM_SPI (typedef dword)
                int PeerSpi; //IPSEC_QM_SPI (typedef dword)
            }
            /// <summary>
            /// See Algos comment.
            /// </summary>
            struct IPSEC_QM_OFFER
            {
                KEY_LIFETIME Lifetime;
                int dwFlags;
                bool bPFSRequired;
                int dwPFSGroup;
                int dwNumAlgos;
                IPSEC_QM_ALGO Algos; //must be 2 in size declared.
            }
            struct IPSEC_QM_POLICY
            {
                Guid gPolicyID;
                string pszPolicyName;
                int dwFlags;
                int dwOfferCount;
                IntPtr pOffers; //PIPSEC_QM_OFFER
            }
        }
    }
}
