using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
namespace IPSecDotNet5
{
    class FriendlyMethods : NativeMethods.Polstore2
    {

        public static int IPSecGetAssignedPolicyData(IntPtr hStore, out IPSEC_POLICY_DATA ipsecPolicyData)
        {
            int hr = IPSecGetAssignedPolicyData(hStore, out IntPtr ipsecPolicyDataPtr);

            if (hr == 0 && ipsecPolicyDataPtr != IntPtr.Zero)
                ipsecPolicyData = Marshal.PtrToStructure<IPSEC_POLICY_DATA>(ipsecPolicyDataPtr);
            else
                ipsecPolicyData = default;

            return hr;
        }

    }
}
