using System;
using System.Runtime.InteropServices;
using static IPSecDotNet5.NativeMethods.Polstructs;
namespace IPSecDotNet5
{
    class Program
    {
        static void Main(string[] args)
        {
            bool runCreate = false;

            IPSec ipsec = new();
            int hr = ipsec.OpenPolicyStore();


            if (runCreate)
            {
                Console.WriteLine("CreateFilterAction");
                hr = ipsec.CreateFilterAction("BlockFilter", IPSec.FilterActionType.Block, out IPSEC_NEGPOL_DATA myFilterAction);
                Console.WriteLine("CreateFilterList");
                hr = ipsec.CreatePortFilter("FilterPorts", new IPSec.Port[] { new IPSec.Port { port = 111, portType = IPSec.PortType.TCP }, new IPSec.Port { port = 222, portType = IPSec.PortType.TCP } }, out IPSEC_FILTER_DATA ipsecFilterData);

                IPSEC_NFA_DATA nfaData = new()
                {
                    NFAIdentifier = Guid.NewGuid(),
                    dwAuthMethodCount = 1,

                };

            }

            ipsec.GetPolicyNFAData(new Guid("d374cbcd-0139-49f7-a74a-bc12cd84014a"), out IPSEC_NFA_DATA testData, out int testCount);


            hr = ipsec.GetAssignedPolicyData(out IPSEC_POLICY_DATA data);
            hr = ipsec.GetISAKMPData(data.ISAKMPIdentifier, out IPSEC_ISAKMP_DATA isakmpdata);
            hr = ipsec.GetSecurityMethods(isakmpdata.pSecurityMethods, out NativeMethods.Oakdefs.CRYPTO_BUNDLE bundle);
            

            ipsec.GetPolicyNFAData(data.PolicyIdentifier, out IPSEC_NFA_DATA ipsecNfaData, out int numNfaObjects);
            #region testing

            #endregion

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
