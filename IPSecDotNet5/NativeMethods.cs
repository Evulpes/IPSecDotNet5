using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Net;

namespace IPSecDotNet5
{
    class NativeMethods
    {
        public class Polstructs
        {
            public static int IPSEC_REGISTRY_PROVIDER = 0;
            public static int IPSEC_DIRECTORY_PROVIDER = 1;
            public static int IPSEC_FILE_PROVIDER = 2;

            //Potentially requires explicit layout.
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
            
            [StructLayout(LayoutKind.Explicit)]
            public struct IPSEC_ISAKMP_DATA
            {
                //First 16 bytes repeat of GUID.
                [FieldOffset(0)]
                public Guid ISAKMPIdentifier;
                [FieldOffset(16)]
                public Guid ISAKMPIdentifierCopy;
                [FieldOffset(32)]
                public IntPtr ISAKMPPolicy; //ISAKMP_POLICY - missing definition.
                [FieldOffset(76)]
                public int dwNumISAKMPSecurityMethods;
                [FieldOffset(80)]
                public IntPtr pSecurityMethods; //PCRYPTO_BUNDLE - missing definition.
                [FieldOffset(88)]
                public int dwWhenChanged;
            }
        
            /// <summary>
            /// 
            /// </summary>
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
        }
        public class Polstore2 : Polstructs
        {
            /// <summary>
            /// 
            /// </summary>
            /// <param name="pszMachineName"></param>
            /// <param name="dwTypeOfStore"></param>
            /// <param name="pszFileName"></param>
            /// <param name="phPolicyStore"></param>
            /// <returns></returns>
            [DllImport("polstore", SetLastError = true)]
            public static extern int IPSecOpenPolicyStore([MarshalAs(UnmanagedType.LPWStr)] string pszMachineName, int dwTypeOfStore, [MarshalAs(UnmanagedType.LPWStr)] string pszFileName, out IntPtr phPolicyStore);
            
            /// <summary>
            /// 
            /// </summary>
            /// <param name="hStore"></param>
            /// <param name="pipspd"></param>
            /// <returns></returns>
            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecGetAssignedPolicyData(IntPtr hStore, out IntPtr pipspd);
        
            /// <summary>
            /// 
            /// </summary>
            /// <param name="hPolicyStore"></param>
            /// <param name="PolicyGuid"></param>
            /// <returns></returns>
            [DllImport("polstore", SetLastError = true)]
            public static extern int IPSecUnassignPolicy(IntPtr hPolicyStore, Guid PolicyGuid);
  
            /// <summary>
            /// 
            /// </summary>
            /// <param name="pIpsecPolicyData"></param>
            [DllImport("polstore", SetLastError = true)]
            protected static extern void IPSecFreePolicyData(IntPtr pIpsecPolicyData);

            /// <summary>
            /// 
            /// </summary>
            /// <param name="hPolicyStore"></param>
            /// <param name="PolicyGuid"></param>
            /// <returns></returns>
            [DllImport("polstore", SetLastError = true)]
            public static extern int IPSecAssignPolicy(IntPtr hPolicyStore, Guid PolicyGuid);

            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecGetISAKMPData(IntPtr hPolicyStore, Guid ISAKMPGUID, IntPtr ppIpsecISAKMPData);

            [DllImport("polstore", SetLastError = true)]
            protected static extern int IPSecGetFilterData(IntPtr hPolicyStore, Guid FilterGUID, IntPtr ppIpsecFilterData);

            [DllImport("polstore", SetLastError = true)]
            public static extern int IPSecCreateFilterData(IntPtr hPolicyStore, IntPtr pIpsecFilterData);
            [DllImport("polstore", SetLastError = true)]
            public static extern int IPSecCreateISAKMPData(IntPtr hPolicyStore, IntPtr pIpsecISAKMPData);
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
    }
}
