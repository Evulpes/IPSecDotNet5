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


            //TestUsageExamples.CreateIpSecFilterLists(hStore);


            int hr = IPSecGetAssignedPolicyData(hStore, out IPSEC_POLICY_DATA test);

            if (hr == 0)
            {
                
                _ = IPSecUnassignPolicy(hStore, test.PolicyIdentifier);
                _ = IPSecAssignPolicy(hStore, test.PolicyIdentifier);
                _ = IPSecGetISAKMPData(hStore, test.ISAKMPIdentifier, out IPSEC_ISAKMP_DATA isakmpData);
                _ = IPSecGetFilterData(hStore, new Guid("ef0eedba-1079-4cfd-8b06-5cc6f62e94c0"), out IPSEC_FILTER_DATA ipsecFilterData);
                _ = IPSecGetFilterSpec(ipsecFilterData.ppFilterSpecs, out IPSEC_FILTER_SPEC filterSpec);

                //ipsecFilterData.pszIpsecName = "testMe";
                //IntPtr pFilterData = Marshal.AllocHGlobal(Marshal.SizeOf(ipsecFilterData));
                //Marshal.StructureToPtr(ipsecFilterData, pFilterData, false);
                //IPSecCreateFilterData(hStore, pFilterData);


            }

        }
    }
}
