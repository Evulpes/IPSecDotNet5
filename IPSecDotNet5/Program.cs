using System;
using System.Runtime.InteropServices;
using static IPSecDotNet5.NativeMethods.Polstructs;
namespace IPSecDotNet5
{
    class Program
    {
        static void Main(string[] args)
        {
            
            IPSec ipsec = new();
            int hr = ipsec.OpenPolicyStore();
            Console.WriteLine("CreateFilterAction");
            hr = ipsec.CreateFilterAction("BlockFilter", IPSec.FilterActionType.Block, out IPSEC_NEGPOL_DATA myFilterAction);
            Console.WriteLine("CreateFilterList");
            hr = ipsec.CreatePortFilterLists("FilterPorts", new IPSec.Port[] { new IPSec.Port { port = 111, portType = IPSec.PortType.TCP }, new IPSec.Port { port = 222, portType = IPSec.PortType.TCP } }, out IPSEC_FILTER_DATA data);
            int brkp = 5;
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
