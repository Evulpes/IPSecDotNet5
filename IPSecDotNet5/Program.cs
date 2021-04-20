using System;
using System.Runtime.InteropServices;
namespace IPSecDotNet5
{
    class Program : FriendlyMethods
    {
        static void Main(string[] args)
        {
            if (IPSecOpenPolicyStore
            (
                string.Empty,
                IPSEC_REGISTRY_PROVIDER,
                string.Empty,
                out IntPtr hStore
            ) != 0)
                throw new Exception();

            int hr = IPSecGetAssignedPolicyData(hStore, out IPSEC_POLICY_DATA test);

            if (hr != 0)
                return;


            _ = IPSecUnassignPolicy(hStore, test.PolicyIdentifier);
            _ = IPSecAssignPolicy(hStore, test.PolicyIdentifier);
            _ = IPSecGetISAKMPData(hStore, test.ISAKMPIdentifier, out IPSEC_ISAKMP_DATA isakmpData);
            _ = IPSecGetFilterData(hStore, new Guid("2e18b647-20dc-4a1c-9404-42306166abbe"), out IPSEC_FILTER_DATA ipsecFilterData);
            _ = IPSecGetFilterSpec(ipsecFilterData.ppFilterSpecs, out IPSEC_FILTER_SPEC filterSpec);



        }
    }
}
