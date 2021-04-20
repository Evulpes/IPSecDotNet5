using System;

namespace IPSecDotNet5
{
    class Program : FriendlyMethods
    {
        static void Main(string[] args)
        {
            if (IPSecOpenPolicyStore
            (
                string.Empty,
                NativeMethods.Unknown.IPSEC_REGISTRY_PROVIDER,
                string.Empty,
                out IntPtr hStore
            ) != 0)
                throw new Exception();

            int hr = IPSecGetAssignedPolicyData(hStore, out IPSEC_POLICY_DATA test);

            if (hr == 0)
            {
                _ = IPSecUnassignPolicy(hStore, test.PolicyIdentifier);
                _ = IPSecAssignPolicy(hStore, test.PolicyIdentifier);


                _ = IPSecGetISAKMPData(hStore, test.ISAKMPIdentifier, out IPSEC_ISAKMP_DATA temp);

                _ = IPSecGetFilterData(hStore, new Guid("10cc0b07-86c0-4477-8f6e-95dc0c67e8f5"), out IPSEC_FILTER_DATA ipsecFilterData);

                int brkp = 0;
            }

            IPSEC_POLICY_DATA myIPSECPolicy = new IPSEC_POLICY_DATA();

            myIPSECPolicy.pszIpsecName = "TestPolicy";
            myIPSECPolicy.pszDescription = "TestDescription";
            
            myIPSECPolicy.pIpsecISAKMPData = IntPtr.Zero;
            //myIPSECPolicy.
            
            
            
            int meme = 5;

        }
    }
}
