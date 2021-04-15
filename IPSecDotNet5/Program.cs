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
                hr = IPSecUnassignPolicy(hStore, test.PolicyIdentifier);
            
            IPSecAssignPolicy(hStore, test.PolicyIdentifier);
            int meme = 5;

        }
    }
}
