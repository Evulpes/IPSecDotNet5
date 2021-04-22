using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace IPSecDotNet5
{
    class TestUsageExamples : FriendlyMethods
    {
        /// <summary>
        /// Creates a filter list with 2 destinational ports. IP addresses do not yet work.
        /// </summary>
        /// <param name="hPolicyStore"></param>
        public static void CreateIpSecFilterLists(IntPtr hPolicyStore)
        {
            IPSEC_FILTER_DATA exampleFilterData = new IPSEC_FILTER_DATA
            {
                dwNumFilterSpecs = 0x2,
                dwWhenChanged = (int)new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds(),
                FilterIdentifier = new Guid("c4cc8fe0-8ddb-48c5-a285-f56c21aba666"),
                ppFilterSpecs = IntPtr.Zero,
                pszIpsecDescription = "ExampleDescription",
                pszIpsecName = "exampleFilterData"
            };
            IPSEC_FILTER_SPEC ExamplePolicyFilterSpec1 = new IPSEC_FILTER_SPEC
            {
                dwMirrorFlag = 0x0,
                FilterSpecGUID = Guid.NewGuid(),
                pszDestDNSName = "",
                pszSrcDNSName = "",
                filter = new NativeMethods.Ipsec.IPSEC_FILTER
                {
                    DstAddr = 0x0,
                    DstMask = 0x0,
                    DstPort = 135,
                    Flags = 0x0,
                    Pad = '\0',
                    Protocol = 0x11,
                    SrcAddr = 0x0,
                    SrcMask = 0x0,
                    SrcPort = 8888,
                    SrcUnknownFlag1 = 1,
                    DstUnknownFlag1 = 0,
                    TunnelAddr = 0,
                    TunnelFilter = false
                },
                pszDescription = "",
                unknownFlag4 = 0x0,
                unknownFlag1 = 0x0
            };
            IPSEC_FILTER_SPEC ExamplePolicyFilterSpec2 = new IPSEC_FILTER_SPEC
            {
                dwMirrorFlag = 0x0,
                FilterSpecGUID = Guid.NewGuid(),
                pszDestDNSName = "",
                pszSrcDNSName = "",
                filter = new NativeMethods.Ipsec.IPSEC_FILTER
                {
                    DstAddr = 0x0,
                    DstMask = 0x0,
                    DstPort = 8080,
                    Flags = 0x0,
                    Pad = '\0',
                    Protocol = 0x6,
                    SrcAddr = 0,
                    SrcMask = 0,
                    SrcPort = 0,
                    SrcUnknownFlag1 = 0,
                    DstUnknownFlag1 = 1,
                    TunnelAddr = 0,
                    TunnelFilter = false
                },
                pszDescription = "",
                unknownFlag1 = 0x0,
                unknownFlag4 = 0x0
            };

            IntPtr pExamplePolicyFilterSpec1 = Marshal.AllocHGlobal(Marshal.SizeOf(ExamplePolicyFilterSpec1));
            Marshal.StructureToPtr(ExamplePolicyFilterSpec1, pExamplePolicyFilterSpec1, false);

            IntPtr pExamplePolicyFilterSpec2 = Marshal.AllocHGlobal(Marshal.SizeOf(ExamplePolicyFilterSpec2));
            Marshal.StructureToPtr(ExamplePolicyFilterSpec2, pExamplePolicyFilterSpec2, false);

            IntPtr ppFilterSpecs = Marshal.AllocHGlobal(Marshal.SizeOf(IntPtr.Size*2));
            Marshal.WriteIntPtr(ppFilterSpecs, pExamplePolicyFilterSpec1);
            Marshal.WriteIntPtr(ppFilterSpecs + IntPtr.Size, pExamplePolicyFilterSpec2);

            exampleFilterData.ppFilterSpecs = ppFilterSpecs;

            IntPtr pExampleFilterData = Marshal.AllocHGlobal(Marshal.SizeOf(exampleFilterData));
            Marshal.StructureToPtr(exampleFilterData, pExampleFilterData, false);
            int loop = IPSecCreateFilterData(hPolicyStore, pExampleFilterData);

            System.Diagnostics.Debug.WriteLine(loop);
            /*netsh ipsec static show all:
                FilterList Name        : exampleFilterData
                Description            : ExampleDescription
                Store                  : Local Store <NCIRMLT001>
                Last Modified          : 22/04/2021 18:47:44
                GUID                   : {C4CC8FE0-8DDB-48C5-A285-F56C21ABA666}
                No. of Filters         : 2
                Filter(s)
                ---------
                Description            : NONE
                Mirrored               : NO
                Source IP Address      : <Any IP Address>
                Source Mask            : 0.0.0.0
                Source DNS Name        : <Any IP Address>
                Destination IP Address : <Any IP Address>
                Destination Mask       : 0.0.0.0
                Destination DNS Name   : <Any IP Address>
                Protocol               : TCP
                Source Port            : ANY
                Destination Port       : 135

                Description            : NONE
                Mirrored               : NO
                Source IP Address      : <Any IP Address>
                Source Mask            : 0.0.0.0
                Source DNS Name        : <Any IP Address>
                Destination IP Address : <Any IP Address>
                Destination Mask       : 0.0.0.0
                Destination DNS Name   : <Any IP Address>
                Protocol               : TCP
                Source Port            : ANY
                Destination Port       : 8080
            */
        }
    }
}
