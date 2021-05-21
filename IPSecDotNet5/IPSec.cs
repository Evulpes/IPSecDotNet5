using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace IPSecDotNet5
{
    class IPSec : FriendlyMethods, IDisposable
    {
        private IntPtr hStore;
        private bool disposedValue;

        public IPSec()
        {
            _ = OpenPolicyStore();
        }

        /// <summary>
        /// Creates a standalone filter action.
        /// </summary>
        /// <param name="hStore">A handle to the policy store.</param>
        /// <param name="name">The name to give the filter action.</param>
        /// <param name="action">The type of action.</param>
        /// <param name="ipsecNegPol">An out struct to return the data.</param>
        /// <param name="description">The description to give the filter action.</param>
        /// <returns>A WinError System Error Code.</returns>
        public int CreateFilterAction(string name, FilterActionType action, out IPSEC_NEGPOL_DATA ipsecNegPol, string description="")
        {
            ipsecNegPol = new IPSEC_NEGPOL_DATA()
            {
                pszIpsecName = name,
                pszDescription = description,
                NegPolType = GUID_NEGOTATION_TYPE_STANDARD,
                NegPolIdentifier = Guid.NewGuid(),
                dwWhenChanged = (int)new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds(),
            };
            if (action == FilterActionType.Block)
                ipsecNegPol.NegPolAction = GUID_NEGOTIATION_ACTION_BLOCK;
            else
                throw new NotImplementedException();
            
            return IPSecCreateNegPolData(hStore, ipsecNegPol);
        }

        /// <summary>
        /// Creates a filter with the specified ports.
        /// </summary>
        /// <param name="name">The name to give the filter .</param>
        /// <param name="ports">The ports to use in the filter .</param>
        /// <param name="ipsecFilterData">An out struct to return the data.</param>
        /// <param name="description">The description to give the filter .</param>
        /// <returns>>A WinError System Error Code.</returns>
        public int CreatePortFilter(string name, Port[] ports, out IPSEC_FILTER_DATA ipsecFilterData, string description="")
        {
            //Initialize.
            ipsecFilterData = new IPSEC_FILTER_DATA()
            {
                pszIpsecName = name,
                pszIpsecDescription = description,
                dwNumFilterSpecs = ports.Length,
                ppFilterSpecs = IntPtr.Zero,
                dwWhenChanged = (int)new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds(),
                FilterIdentifier = Guid.NewGuid(),
            };

            //Create an array of filter specs for each specified port.
            IPSEC_FILTER_SPEC[] filterSpecs = new IPSEC_FILTER_SPEC[ports.Length];

            //Create an array of pointers to allocation.
            IntPtr[] pFilterSpecs = new IntPtr[ports.Length];

            for (int i = 0; i < ports.Length; i++)
            {
                //Initialize a spec.
                filterSpecs[i] = new()
                {
                    dwMirrorFlag = 0x0,
                    FilterSpecGUID = Guid.NewGuid(),
                    pszDescription = "",
                    pszSrcDNSName = "",
                    filter = new NativeMethods.Ipsec.IPSEC_FILTER
                    {
                        Flags = 0x0,
                        Pad = '\0',
                        TunnelAddr = 0,
                        TunnelFilter = false
                    }
                
                };
                if (ports[i].portType == PortType.TCP)
                {
                    filterSpecs[i].filter.DstPort = ports[i].port;
                    filterSpecs[i].filter.Protocol = (int)PortType.TCP;
                    filterSpecs[i].filter.DstUnknownFlag1 = 0x1;
                }
                else
                {
                    filterSpecs[i].filter.SrcPort = ports[i].port;
                    filterSpecs[i].filter.Protocol = (int)PortType.UDP;
                    filterSpecs[i].dwMirrorFlag = 0x1;
                    filterSpecs[i].filter.SrcUnknownFlag1 = 0x1;
                }

                //Marshal the struct to a pointer.
                pFilterSpecs[i] = Marshal.AllocHGlobal(Marshal.SizeOf(filterSpecs[i]));
                Marshal.StructureToPtr(filterSpecs[i], pFilterSpecs[i], false);


            }

            //Create the 2d pointer and write the struct pointers sequentially next to each other.
            IntPtr ppFilterSpecs = Marshal.AllocHGlobal(IntPtr.Size * ports.Length);
            IntPtr ptrCopy = ppFilterSpecs;
            for (int i = 0; i < ports.Length; i++)
            {
                Marshal.WriteIntPtr(ptrCopy, pFilterSpecs[i]);
                ptrCopy += IntPtr.Size;
            }
            ipsecFilterData.ppFilterSpecs = ppFilterSpecs;


            //Call the FriendlyMethod native.
            int hr = IPSecCreateFilterData(hStore, ipsecFilterData);


            //Free unmanaged memory.
            for (int i = 0; i < ports.Length; i++)
                Marshal.FreeHGlobal(pFilterSpecs[i]);

            Marshal.FreeHGlobal(ppFilterSpecs);
            return hr;
        }

        public int TEMP_CREATEIPSECSAKMPDATA(IPSEC_ISAKMP_DATA data)
        {
            int hr = FriendlyMethods.IPSecCreateISAKMPData(hStore, data);
            return hr;
        }

        /// <summary>
        /// Opens a handle to the policy store.
        /// </summary>
        /// <returns>A WinError System Error Code.</returns>
        public int OpenPolicyStore()
        {
            return IPSecOpenPolicyStore
            (
                string.Empty,
                IPSEC_REGISTRY_PROVIDER,
                string.Empty,
                out hStore
            );
        }

        public int GetAssignedPolicyData(out IPSEC_POLICY_DATA assignedPolicyData) => IPSecGetAssignedPolicyData(hStore, out  assignedPolicyData);

        public int GetISAKMPData(Guid ISAKMPGUID, out IPSEC_ISAKMP_DATA ipsecIsakmpData)=> IPSecGetISAKMPData(hStore, ISAKMPGUID, out ipsecIsakmpData);

        public int GetSecurityMethods(IntPtr pSecurityMethods, out NativeMethods.Oakdefs.CRYPTO_BUNDLE securityMethods)
        {
            securityMethods = (NativeMethods.Oakdefs.CRYPTO_BUNDLE)Marshal.PtrToStructure(pSecurityMethods, typeof(NativeMethods.Oakdefs.CRYPTO_BUNDLE));


            return 0;
        }
        
        /// <summary>
        /// Closes a handle to the policy store.
        /// </summary>
        /// <returns>>A WinError System Error Code.</returns>
        public int ClosePolicyStore() => IPSecClosePolicyStore(hStore);

        
        public enum FilterActionType
        {
            Allow,
            Block,
        }
        public struct Port
        {
            public ushort port;
            public PortType portType;
        }
        public enum PortType
        {
            TCP = 0x6,
            UDP = 0x11
        }
        #region dispose
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer

                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~IPSec()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }

}
