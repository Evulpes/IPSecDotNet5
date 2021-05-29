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
        private Guid policyId;

        public IPSec()
        {
            _ = OpenPolicyStore();
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="ports"></param>
        /// <returns></returns>
        public int ArmPorts(Port[] ports)
        {
            if (hStore == IntPtr.Zero)
                return 0x6; // ERROR_INVALID_HANDLE

            int hresult = IPSecGetAssignedPolicyData(hStore, out IPSEC_POLICY_DATA ipsecPolicyData);
            if (hresult == 0)
            {
                throw new NotImplementedException("ToDo: Add IPSecEnumPolicyData and deletion");
            }


            hresult = CreateIpsecSakmpData(out IPSEC_ISAKMP_DATA ipsecIsakmpData);
            if (hresult != 0)
                return hresult;

            IPSEC_POLICY_DATA policyData = new()
            {
                pszIpsecName = "IPSecDotNet5 Policy",
                pszDescription = "https://github.com/Evulpes/IPSecDotNet5/",
                PolicyIdentifier = Guid.NewGuid(),
                pIpsecISAKMPData = IntPtr.Zero,
                ppIpsecNFAData = IntPtr.Zero,
                dwNumNFACount = 0,
                dwWhenChanged = 0,
                dwPollingInterval = 0,
                ISAKMPIdentifier = ipsecIsakmpData.ISAKMPIdentifier,
            };

            hresult = CreatePolicy(policyData);
            if (hresult != 0)
                return hresult;

            policyId = policyData.PolicyIdentifier;

            hresult = CreateFilterAction("IPSecDotNet5 Filter Action", FilterActionType.Block, out IPSEC_NEGPOL_DATA filterAction);
            if (hresult != 0)
                return hresult;

            hresult = CreatePortFilter("IPSecDotNet5 Filter List", ports, out IPSEC_FILTER_DATA filterData);
            if (hresult != 0)
                return hresult;

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
                pszIpsecName = "IPSecDotNet5 Rule",
                pszDescription = "https://github.com/Evulpes/IPSecDotNet5/",
                pszInterfaceName = null,
                pszEndPointName = null,
                NFAIdentifier = Guid.NewGuid(),
                pIpsecFilterData = new(),
                FilterIdentifier = filterData.FilterIdentifier,
                NegPolIdentifier = filterAction.NegPolIdentifier,
                dwTunnelFlags = 0,
                dwInterfaceType = (uint)InterfaceType.All,
                dwActiveFlag = 1,
                dwAuthMethodCount = 1,
                ppAuthMethods = ppAuthMethods,
                dwWhenChanged = (int)new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds(),
            };

            hresult = CreateRule(policyData.PolicyIdentifier, nfaData);

            Marshal.FreeHGlobal(ppAuthMethods);
            Marshal.FreeHGlobal(pAuthMethods);

            return hresult;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public int UnblockPorts() => UnassignPolicy(policyId);
        public int BlockPorts() => AssignPolicy(policyId);

        /// <summary>
        /// Assigns the specified policy to the engine.
        /// </summary>
        /// <param name="policyIdentifier">The GUID of the policy to assign.</param>
        /// <returns>A WinError System Error Code.</returns>
        private int AssignPolicy(Guid policyIdentifier) => IPSecAssignPolicy(hStore, policyIdentifier);
        /// <summary>
        /// Unassigns the specified policy from the engine.
        /// </summary>
        /// <param name="policyIdentifier">The GUID of the policy to unassign.</param>
        /// <returns>A WinError System Error Code.</returns>
        private int UnassignPolicy(Guid policyIdentifier) => IPSecUnassignPolicy(hStore, policyIdentifier);
        /// <summary>
        /// Creates a standalone filter action.
        /// </summary>
        /// <param name="hStore">A handle to the policy store.</param>
        /// <param name="name">The name to give the filter action.</param>
        /// <param name="action">The type of action.</param>
        /// <param name="ipsecNegPol">An out struct to return the data.</param>
        /// <param name="description">The description to give the filter action.</param>
        /// <returns>A WinError System Error Code.</returns>
        private int CreateFilterAction(string name, FilterActionType action, out IPSEC_NEGPOL_DATA ipsecNegPol, string description="")
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
        private int CreatePortFilter(string name, Port[] ports, out IPSEC_FILTER_DATA ipsecFilterData, string description="")
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
        /// <summary>
        /// 
        /// </summary>
        /// <param name="policyIdentifier"></param>
        /// <param name="ipsecNFAData"></param>
        /// <returns></returns>
        private int CreateRule(Guid policyIdentifier, IPSEC_NFA_DATA ipsecNFAData) => IPSecCreateNFAData(hStore, policyIdentifier, ipsecNFAData);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="ipsecPolicyData"></param>
        /// <returns></returns>
        private int CreatePolicy(IPSEC_POLICY_DATA ipsecPolicyData)
        {    
            int hr = IPSecCreatePolicyData(hStore, ipsecPolicyData);
            return hr;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="manualISAKMPData"></param>
        /// <returns></returns>
        private int CreateIpsecSakmpData(out IPSEC_ISAKMP_DATA manualISAKMPData)
        {
            NativeMethods.Oakdefs.CRYPTO_BUNDLE pSecurityMethods = new()
            {
                EncryptionAlgorithm = new NativeMethods.Oakdefs.OAKLEY_ALGORITHM() { AlgorithmIdentifier = 3, Rounds = 8, KeySize = 64 },
                HashAlgorithm = new NativeMethods.Oakdefs.OAKLEY_ALGORITHM() { AlgorithmIdentifier = 2, Rounds = 0, KeySize = 64 },
                Lifetime = new NativeMethods.Oakdefs.OAKLEY_LIFETIME() { KBytes = 0, Seconds = 28800 },
            };
            manualISAKMPData = new IPSEC_ISAKMP_DATA()
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
        
            int hr = IPSecCreateISAKMPData(hStore, manualISAKMPData);

            Marshal.FreeHGlobal(manualISAKMPData.pSecurityMethods);

            return hr;
        }
        /// <summary>
        /// Opens a handle to the policy store.
        /// </summary>
        /// <returns>A WinError System Error Code.</returns>
        private int OpenPolicyStore()
        {
            return IPSecOpenPolicyStore
            (
                string.Empty,
                IPSEC_REGISTRY_PROVIDER,
                string.Empty,
                out hStore
            );
        }
        /// <summary>
        /// Closes a handle to the policy store.
        /// </summary>
        /// <returns>>A WinError System Error Code.</returns>
        private int ClosePolicyStore() => IPSecClosePolicyStore(hStore);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="assignedPolicyData"></param>
        /// <returns></returns>
        private int GetAssignedPolicyData(out IPSEC_POLICY_DATA assignedPolicyData) => IPSecGetAssignedPolicyData(hStore, out  assignedPolicyData);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="ISAKMPGUID"></param>
        /// <param name="ipsecIsakmpData"></param>
        /// <returns></returns>
        private int GetISAKMPData(Guid ISAKMPGUID, out IPSEC_ISAKMP_DATA ipsecIsakmpData)=> IPSecGetISAKMPData(hStore, ISAKMPGUID, out ipsecIsakmpData);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="pSecurityMethods"></param>
        /// <param name="securityMethods"></param>
        /// <returns></returns>
        private int GetSecurityMethods(IntPtr pSecurityMethods, out NativeMethods.Oakdefs.CRYPTO_BUNDLE securityMethods)
        {
            //Try ~Catch manage? Need to test overall.
            securityMethods = (NativeMethods.Oakdefs.CRYPTO_BUNDLE)Marshal.PtrToStructure(pSecurityMethods, typeof(NativeMethods.Oakdefs.CRYPTO_BUNDLE));
            return 0;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="policyGuid"></param>
        /// <param name="ipsecNfaData"></param>
        /// <param name="numNfaObjects"></param>
        /// <returns></returns>
        private int GetPolicyNFAData(Guid policyGuid, out IPSEC_NFA_DATA ipsecNfaData, out int numNfaObjects) => IPSecEnumNFAData(hStore, policyGuid, out ipsecNfaData, out numNfaObjects);
         
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
        /// <summary>
        /// Used for <see cref="Port.portType"/>.
        /// </summary>
        public enum PortType
        {
            TCP = 0x6,
            UDP = 0x11
        }
        /// <summary>
        /// Used for <see cref="NativeMethods.Polstructs.IPSEC_NFA_DATA.dwInterfaceType"/>.
        /// </summary>
        public enum InterfaceType : uint
        {
            dialup = 0xFFFFFFFF,
            LAN = 0xFFFFFFFE,
            All = 0xFFFFFFFD,
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }
                ClosePolicyStore();
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
    }

}
