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
                filter = new NativeMethods.Unknown.IPSEC_FILTER
                {
                    DstAddr = 0x0,
                    DstMask = 0x0,
                    DstPort = 135,
                    Flags = 0x0,
                    Pad = '\0',
                    Protocol = 0x6,
                    SrcAddr = 0x0,
                    SrcMask = 0x0,
                    SrcPort = 0,
                    SrcPortCount = 0,
                    DstPortCount = 1,
                    TunnelAddr = 0,
                    TunnelFilter = false
                },
                pszDescription = "",
                sourceAddressLength = 0x0,
                sourceAddressExists = 0x0
            };
            IPSEC_FILTER_SPEC ExamplePolicyFilterSpec2 = new IPSEC_FILTER_SPEC
            {
                dwMirrorFlag = 0x0,
                FilterSpecGUID = Guid.NewGuid(),
                pszDestDNSName = "",
                pszSrcDNSName = "",
                filter = new NativeMethods.Unknown.IPSEC_FILTER
                {
                    DstAddr = 0x0,
                    DstMask = 0x0,
                    DstPort = 8080,
                    Flags = 0x0,
                    Pad = '\0',
                    Protocol = 0x6,
                    SrcAddr = 0x0,
                    SrcMask = 0x0,
                    SrcPort = 0,
                    SrcPortCount = 0,
                    DstPortCount = 1,
                    TunnelAddr = 0,
                    TunnelFilter = false
                },
                pszDescription = "",
                sourceAddressLength = 0x0,
                sourceAddressExists = 0x0
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
        }
    }
}
