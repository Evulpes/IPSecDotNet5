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

            if (hr != 0)
                return;


            _ = IPSecUnassignPolicy(hStore, test.PolicyIdentifier);
            _ = IPSecAssignPolicy(hStore, test.PolicyIdentifier);


            _ = IPSecGetISAKMPData(hStore, test.ISAKMPIdentifier, out IPSEC_ISAKMP_DATA temp);

            _ = IPSecGetFilterData(hStore, new Guid("3980bbd0-5120-41c6-bda3-8005f877d7e2"), out IPSEC_FILTER_DATA ipsecFilterData);


            IntPtr tempPTr = System.Runtime.InteropServices.Marshal.ReadIntPtr(ipsecFilterData.ppFilterSpecs);
            IPSEC_FILTER_SPEC fs = (IPSEC_FILTER_SPEC)System.Runtime.InteropServices.Marshal.PtrToStructure(tempPTr, typeof(IPSEC_FILTER_SPEC));


            int brkp = 0;
            

        }
    }
}
