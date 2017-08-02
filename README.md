# WirelessHART-Parser
Wireshark dissector for wirelessHART

This will eventually work with changes to KillerBee to allow live capture of
WirelessHART.

Installation:

Copy wirelesshart.lua to your ~/.wireshark/plugins/ directory

Notes:

hart-test.pcap was made by sniffing wirelesshart beacons from a Linear Technologies WirelessHART development kit's base station in default configuration.

Note that the WirelessHART parser will choke on part of these beacon frames, this is an error in the parser I suspect, to be remedied Real Soon Now(tm).
