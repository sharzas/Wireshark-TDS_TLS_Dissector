# Wireshark-TDS_TLS_Dissector
Wireshark Dissector plugin, which enables parsing of the TLS payload in TDS prelogin messages (SQL). This enables Wireshark to parse TLS handshake (Client Hello/Server Hello/Change Cipher Spec etc) for TDS connections.

This is not by any means a "real" dissector. It was written to overcome the fact that
Wireshark 3.6.x doesn't chain the TLS records inside TDS prelogin packets to the TLS dissector,
resulting in TDS prelogin packets indicating a TLS Exchange, but the details of the TLS
record, including handshake is missing.

This is of course implemented in Wireshark v4.0, it is however, still in Release Candidate
state, so we can't use that for production yet.

This dissector invokes the default TDS dissector to get all the original information
provided about TDS packets by Wireshark, and then checks for a TLS payload if the TDS
packet is a prelogin message, which if detected, will trigger a call to the TLS dissector, 
with the TLS payload data.
