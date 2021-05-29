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
          
            int hresult = ipsec.ArmPorts(new IPSec.Port[] { new IPSec.Port { port = 443, portType = IPSec.PortType.TCP }, new IPSec.Port { port = 443, portType = IPSec.PortType.UDP } } );
            
            
            hresult = ipsec.BlockPorts();
            
            hresult = ipsec.UnblockPorts();


        

            

            //hr = ipsec.GetAssignedPolicyData(out IPSEC_POLICY_DATA data);
            //hr = ipsec.GetISAKMPData(data.ISAKMPIdentifier, out IPSEC_ISAKMP_DATA isakmpdata);
            //hr = ipsec.GetSecurityMethods(isakmpdata.pSecurityMethods, out NativeMethods.Oakdefs.CRYPTO_BUNDLE bundle);
            //hr = ipsec.GetPolicyNFAData(data.PolicyIdentifier, out IPSEC_NFA_DATA ipsecNfaData, out int numNfaObjects);
            //IPSEC_AUTH_METHOD temp = (IPSEC_AUTH_METHOD)Marshal.PtrToStructure(Marshal.ReadIntPtr(ipsecNfaData.ppAuthMethods), typeof(IPSEC_AUTH_METHOD));




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
