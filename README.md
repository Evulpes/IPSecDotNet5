# IPSecDotNet5

    netsh ipsec static add policy ExamplePolicy
    netsh ipsec static add filterlist ExampleFilterList
    netsh ipsec static add filter filterlist=ExampleFilterList srcaddr=any dstaddr=any protocol=tcp dstport=8080
    netsh ipsec static add filteraction ExampleFilterAction action=block
    netsh ipsec static add rule name=ExampleRule policy=ExamplePolicy filterlist=ExampleFilterList filteraction=ExampleFilterAction
    netsh ipsec static set policy ExamplePolicy assign=y

# Progress:
    netsh ipsec static add policy ExamplePolicy
    netsh ipsec static add filterlist ExampleFilterList ##Most likely not required.
    ipsec.CreatePortFilter("ExampleFilterList", new IPSec.Port[] { new IPSec.Port { port = 8080, portType = IPSec.PortType.TCP } }, out IPSEC_FILTER_DATA data);
    ipsec.CreateFilterAction("ExampleFilterAction", IPSec.FilterActionType.Block, out IPSEC_NEGPOL_DATA myFilterAction);
    netsh ipsec static add rule name=ExampleRule policy=ExamplePolicy filterlist=ExampleFilterList filteraction=ExampleFilterAction
    netsh ipsec static set policy ExamplePolicy assign=y

https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-GPIPSEC/%5BMS-GPIPSEC%5D.pdf
