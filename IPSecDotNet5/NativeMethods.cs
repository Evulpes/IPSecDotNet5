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
                [FieldOffset(16)]
                public Guid ISAKMPIdentifier;
                [FieldOffset(32)]
                public IntPtr ISAKMPPolicy; //ISAKMP_POLICY - missing definition
                [FieldOffset(76)]
                public int dwNumISAKMPSecurityMethods;
                [FieldOffset(80)]
                public IntPtr pSecurityMethods;
                [FieldOffset(88)]
                public int dwWhenChanged;
            }
        
            public struct IPSEC_FILTER_DATA
            {
                public Guid FilterIdentifier;
                public int dwNumFilterSpecs;
                public IntPtr ppFilterSpecs;
                public int dwWhenChanged;
                [MarshalAs(UnmanagedType.LPWStr)] public string pszIpsecName;
                [MarshalAs(UnmanagedType.LPWStr)] public string pszIpsecDescription;
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
        }
        public static class Unknown
        {
            public static int IPSEC_REGISTRY_PROVIDER = 0;
        }
    }
}
