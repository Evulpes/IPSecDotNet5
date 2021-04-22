# IPSecDotNet5
    netsh ipsec static add policy ExamplePolicy
    netsh ipsec static add filterlist ExampleFilterListnetsh ipsec static add filter filterlist=ExampleFilterList srcaddr=8.8.8.8 srcmask=255.255.255.0 dstaddr=9.9.9.9 dstmask=255.255.255.0 protocol=tcp dstport=8080 srcport=9090
    netsh ipsec static add filteraction ExampleFilterAction action=block
    netsh ipsec static add rule name=ExampleRule policy=ExamplePolicy filterlist=ExampleFilterList filteraction=ExampleFilterAction
    netsh ipsec static set policy ExamplePolicy assign=y
