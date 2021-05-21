﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
namespace IPSecDotNet5
{
    class FriendlyMethods : NativeMethods.Polstore2
    {

        protected static int IPSecGetAssignedPolicyData(IntPtr hStore, out IPSEC_POLICY_DATA ipsecPolicyData)
        {
            int hr = IPSecGetAssignedPolicyData(hStore, out IntPtr ipsecPolicyDataPtr);

            if (hr == 0 && ipsecPolicyDataPtr != IntPtr.Zero)
                ipsecPolicyData = Marshal.PtrToStructure<IPSEC_POLICY_DATA>(ipsecPolicyDataPtr);
            else
                ipsecPolicyData = default;

            return hr;
        }
        protected static int IPSecGetISAKMPData(IntPtr hStore, Guid ISAKMPGUID, out IPSEC_ISAKMP_DATA ipsecISAKMPData)
        {
            ipsecISAKMPData = new IPSEC_ISAKMP_DATA();

            //Allocate memory for the struct pointer.
            IntPtr ppIpsecISAKMPData = Marshal.AllocHGlobal(Marshal.SizeOf(new IntPtr()));
            
            
            int hr = IPSecGetISAKMPData(hStore, ISAKMPGUID, ppIpsecISAKMPData);
            if (hr != 0)
                return hr;

            //Dereference the ppIpsecISAKMPData into a pointer.
            IntPtr pIpsecISAKMPData = Marshal.ReadIntPtr(ppIpsecISAKMPData);

            //Cast the ptr.
            ipsecISAKMPData = (IPSEC_ISAKMP_DATA)Marshal.PtrToStructure(pIpsecISAKMPData, typeof(IPSEC_ISAKMP_DATA));

            //Free memory allocations.
            Marshal.FreeHGlobal(ppIpsecISAKMPData);

            return hr;
        }
        protected static int IPSecGetNegPolData(IntPtr hStore, Guid negGuid, out IPSEC_NEGPOL_DATA ipsecNegPolData)
        {
            ipsecNegPolData = new IPSEC_NEGPOL_DATA();

            //Allocate memory for the struct pointer.
            IntPtr ppIpsecNegPolData = Marshal.AllocHGlobal(Marshal.SizeOf(new IntPtr()));

            //Execute the native import.
            int hr = IPSecGetNegPolData(hStore, negGuid, ppIpsecNegPolData);
            if (hr != 0)
                return hr;

            //Dereference the double pointer once.
            IntPtr pIpsecNegPolData = Marshal.ReadIntPtr(ppIpsecNegPolData);

            //Marshal the dereferenced pointer to a structure.
            ipsecNegPolData = (IPSEC_NEGPOL_DATA)Marshal.PtrToStructure(pIpsecNegPolData, typeof(IPSEC_NEGPOL_DATA));

            //Free memory.
            Marshal.FreeHGlobal(ppIpsecNegPolData);
            return hr;
        }
        protected static int IPSecGetFilterData(IntPtr hStore, Guid filterGuid, out IPSEC_FILTER_DATA ipsecFilterData)
        {
            ipsecFilterData = new IPSEC_FILTER_DATA();
            
            //Allocate memory for the struct pointer.
            IntPtr ppIpsecFilterData = Marshal.AllocHGlobal(Marshal.SizeOf(new IntPtr()));

            int hr = IPSecGetFilterData(hStore, filterGuid, ppIpsecFilterData);
            if (hr != 0)
                return hr;

            //Dereference the ppIpsecISAKMPData into a pointer.
            IntPtr pIpsecFilterData = Marshal.ReadIntPtr(ppIpsecFilterData);

            ipsecFilterData = (IPSEC_FILTER_DATA)Marshal.PtrToStructure(pIpsecFilterData, typeof(IPSEC_FILTER_DATA));

            Marshal.FreeHGlobal(ppIpsecFilterData);
            return hr;
        }
        protected static int IPSecGetFilterSpec(IntPtr ppFilterSpecs, out IPSEC_FILTER_SPEC filterSpecs)
        {
            filterSpecs = new IPSEC_FILTER_SPEC();
            if (ppFilterSpecs == IntPtr.Zero)
                return 1;
            
            filterSpecs = (IPSEC_FILTER_SPEC)Marshal.PtrToStructure(Marshal.ReadIntPtr(ppFilterSpecs), typeof(IPSEC_FILTER_SPEC));
            return 0;
        }
        protected static int IPSecCreateNegPolData(IntPtr hStore, IPSEC_NEGPOL_DATA ipsecNegPolData)
        {

            IntPtr pIpsecNegPolData = Marshal.AllocHGlobal(Marshal.SizeOf(ipsecNegPolData));
            Marshal.StructureToPtr(ipsecNegPolData, pIpsecNegPolData, false);


            int hr = IPSecCreateNegPolData(hStore, pIpsecNegPolData);

            Marshal.FreeHGlobal(pIpsecNegPolData);
            return hr;
        }
        protected static int IPSecCreateFilterData(IntPtr hStore, IPSEC_FILTER_DATA ipsecFilterData)
        {
            IntPtr pExampleFilterData = Marshal.AllocHGlobal(Marshal.SizeOf(ipsecFilterData));
            Marshal.StructureToPtr(ipsecFilterData, pExampleFilterData, false);

            int hr = IPSecCreateFilterData(hStore, pExampleFilterData);

            Marshal.FreeHGlobal(pExampleFilterData);
            return hr;
        }
    }
}
