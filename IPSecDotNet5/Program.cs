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


            int hrTest = IPSecGetNegPolData(hStore, new Guid("7cdf3111-4c61-4f3b-8785-7a31c1016738"), out IPSEC_NEGPOL_DATA temp);
            TestUsageExamples.CreateIpSecFilterLists(hStore);


            int hr = IPSecGetAssignedPolicyData(hStore, out IPSEC_POLICY_DATA test);

            if (hr == 0)
            {
                
                _ = IPSecUnassignPolicy(hStore, test.PolicyIdentifier);
                _ = IPSecAssignPolicy(hStore, test.PolicyIdentifier);
                _ = IPSecGetISAKMPData(hStore, test.ISAKMPIdentifier, out IPSEC_ISAKMP_DATA isakmpData);
                _ = IPSecGetFilterData(hStore, new Guid("ef0eedba-1079-4cfd-8b06-5cc6f62e94c0"), out IPSEC_FILTER_DATA ipsecFilterData);
                _ = IPSecGetFilterSpec(ipsecFilterData.ppFilterSpecs, out IPSEC_FILTER_SPEC filterSpec);

                int mememe = 5;

            }

        }
    }
}
