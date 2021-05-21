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


            //Console.WriteLine("CreateFilterAction");
            //hr = ipsec.CreateFilterAction("BlockFilter", IPSec.FilterActionType.Block, out IPSEC_NEGPOL_DATA myFilterAction);

            //Console.WriteLine("CreateFilterList");
            //hr = ipsec.CreatePortFilterLists("FilterPorts", new IPSec.Port[] { new IPSec.Port { port = 111, portType = IPSec.PortType.TCP }, new IPSec.Port { port = 222, portType = IPSec.PortType.TCP } }, out IPSEC_FILTER_DATA data);


            hr = ipsec.GetAssignedPolicyData(out IPSEC_POLICY_DATA data);
            hr = ipsec.GetISAKMPData(data.ISAKMPIdentifier, out IPSEC_ISAKMP_DATA isakmpdata);
            hr = ipsec.GetSecurityMethods(isakmpdata.pSecurityMethods, out NativeMethods.Oakdefs.CRYPTO_BUNDLE bundle);
            int temp = 0;


            NativeMethods.Oakdefs.CRYPTO_BUNDLE pSecurityMethods = new NativeMethods.Oakdefs.CRYPTO_BUNDLE()
            {
                EncryptionAlgorithm = new NativeMethods.Oakdefs.OAKLEY_ALGORITHM() { AlgorithmIdentifier = 3, Rounds = 8, KeySize = 64 },
                HashAlgorithm = new NativeMethods.Oakdefs.OAKLEY_ALGORITHM() {AlgorithmIdentifier = 2, Rounds = 0, KeySize =  64},
                Lifetime = new NativeMethods.Oakdefs.OAKLEY_LIFETIME() { KBytes = 0, Seconds = 28800 },
            };

            IPSEC_ISAKMP_DATA manualISAKMPData = new IPSEC_ISAKMP_DATA()
            {
                ISAKMPIdentifier = Guid.NewGuid(),
                dwWhenChanged = (int)new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds(),
                dwNumISAKMPSecurityMethods = 2,
                pSecurityMethods = Marshal.AllocHGlobal(Marshal.SizeOf(pSecurityMethods)),
            };
            manualISAKMPData.ISAKMPPolicy = new NativeMethods.Oakdefs.ISAKMP_POLICY()
            {
                AquireSize = 28800,
                PolicyId = manualISAKMPData.ISAKMPIdentifier
                
            };
            Marshal.StructureToPtr(pSecurityMethods, manualISAKMPData.pSecurityMethods, false);

            int meme = ipsec.TEMP_CREATEIPSECSAKMPDATA(manualISAKMPData);



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
