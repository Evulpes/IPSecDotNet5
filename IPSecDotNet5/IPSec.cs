using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static IPSecDotNet5.NativeMethods.Polstructs;
using static IPSecDotNet5.NativeMethods.Polstore2;
namespace IPSecDotNet5
{
    class IPSec : FriendlyMethods
    {
        private IntPtr hStore;
        public IPSec()
        {
            
            OpenPolicyStore();
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

            
            return IPSecCreateNegPolData(hStore, ipsecNegPol);
        }
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
        public enum FilterActionType
        {
            Allow,
            Block,
        }
    }

}
