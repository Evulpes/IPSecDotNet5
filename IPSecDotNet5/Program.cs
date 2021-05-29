using System;
using System.Runtime.InteropServices;
using static IPSecDotNet5.NativeMethods.Polstructs;
namespace IPSecDotNet5
{
    class Program
    {
        static void Main(string[] args)
        {
            bool runCreate = true;

            IPSec ipsec = new();
            int hr = ipsec.OpenPolicyStore();


            if (runCreate)
            {
                Console.WriteLine("CreateFilterAction");
                hr = ipsec.CreateFilterAction("BlockFilter", IPSec.FilterActionType.Block, out IPSEC_NEGPOL_DATA myFilterAction);
                Console.WriteLine("CreateFilterList");
                hr = ipsec.CreatePortFilter("FilterPorts", new IPSec.Port[] { new IPSec.Port { port = 111, portType = IPSec.PortType.TCP }, new IPSec.Port { port = 222, portType = IPSec.PortType.TCP } }, out IPSEC_FILTER_DATA ipsecFilterData);

                IPSEC_AUTH_METHOD ipsecAuthMethod = new()
                {
                    dwAuthType = 0x5
                };
                IntPtr pAuthMethods = Marshal.AllocHGlobal(Marshal.SizeOf(ipsecAuthMethod));
                IntPtr ppAuthMethods = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(ppAuthMethods, pAuthMethods);
                Marshal.StructureToPtr(ipsecAuthMethod, pAuthMethods, false);


                IPSEC_NFA_DATA nfaData = new()
                {
                    pszIpsecName = "Example Rule",
                    pszDescription = "Example Rule Description",
                    pszInterfaceName = null,
                    pszEndPointName = null,
                    NFAIdentifier = Guid.NewGuid(),
                    pIpsecFilterData = new(),
                    FilterIdentifier = default,
                    NegPolIdentifier = myFilterAction.NegPolIdentifier,
                    dwTunnelFlags = 0,
                    dwInterfaceType = unchecked(0xfffffd),
                    dwActiveFlag = 1,
                    dwAuthMethodCount = 1,
                    ppAuthMethods = ppAuthMethods,
                    dwWhenChanged = (int)new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds(),
                };
                hr = ipsec.CreateRule(new Guid("2ad0e328-7fa8-41a4-a42a-25eec476178b"), nfaData);
            }

            hr = ipsec.GetAssignedPolicyData(out IPSEC_POLICY_DATA data);
            hr = ipsec.GetISAKMPData(data.ISAKMPIdentifier, out IPSEC_ISAKMP_DATA isakmpdata);
            hr = ipsec.GetSecurityMethods(isakmpdata.pSecurityMethods, out NativeMethods.Oakdefs.CRYPTO_BUNDLE bundle);
            hr = ipsec.GetPolicyNFAData(data.PolicyIdentifier, out IPSEC_NFA_DATA ipsecNfaData, out int numNfaObjects);
            IPSEC_AUTH_METHOD temp = (IPSEC_AUTH_METHOD)Marshal.PtrToStructure(Marshal.ReadIntPtr(ipsecNfaData.ppAuthMethods), typeof(IPSEC_AUTH_METHOD));

            //Internalise?
            hr = ipsec.CreateIpsecSakmpData();



            int tempendbrkp = 5;

            //TestUsageExamples.CreateIpSecFilterLists(hStore);
            //TestUsageExamples.CreateFilterAction(hStore);

            //int hr = IPSecGetAssignedPolicyData(hStore, out IPSEC_POLICY_DATA test);

            //if (hr == 0)
            //{

            //    _ = IPSecUnassignPolicy(hStore, test.PolicyIdentifier);
            //    _ = IPSecAssignPolicy(hStore, test.PolicyIdentifier);
            //    _ = IPSecGetISAKMPData(hStore, test.ISAKMPIdentifier, out IPSEC_ISAKMP_DATA isakmpData);
            //    _ = IPSecGetFilterData(hStore, new Guid("ef0eedba-1079-4cfd-8b06-5cc6f62e94c0"), out IPSEC_FILTER_DATA ipsecFilterData);
            //    _ = IPSecGetFilterSpec(ipsecFilterData.ppFilterSpecs, out IPSEC_FILTER_SPEC filterSpec);

            //    int mememe = 5;

            //}

        }
    }
}
