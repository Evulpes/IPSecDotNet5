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

            public struct IPSEC_POLICY_DATA
            {
                public Guid PolicyIdentifier;
                int dwPollingInterval;
                IntPtr pIpsecISAKMPData;
                IntPtr ppIpsecNFAData;
                int dwNumNFACount;
                int dwWhenChanged;
                [MarshalAs(UnmanagedType.LPWStr)] string pszIpsecName;
                [MarshalAs(UnmanagedType.LPWStr)] string pszDescription;
                Guid ISAKMPIdentifier;
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
        }
        public static class Unknown
        {
            public static int IPSEC_REGISTRY_PROVIDER = 0;
        }
    }
}
