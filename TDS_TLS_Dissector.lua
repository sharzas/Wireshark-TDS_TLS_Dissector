--[[
    LUA Dissector for TDS TLS Information

    Author : Kenneth Nielsen (ken@jndata.dk)
    Version: 1.0
    License: GNU General Public License v3.0

    Description:
    This is not by any means a "real" dissector. It was written to overcome the fact that
    Wireshark doesn't chain the TLS records inside TDS prelogin packets to the TLS dissector,
    resulting in TDS prelogin packets indicating a TLS Exchange, but the details of the TLS
    record, including handshake is missing.

    This is of course implemented in Wireshark v4.0, it is however, still in Release Candidate
    state, so we can't use that for production yet.

    This dissector invokes the default TDS dissector to get all the original information
    provided about TDS packets by Wireshark, and then checks for a TLS payload if the TDS
    packet is a prelogin message, which if detected, will trigger a call to the TLS dissector, 
    with the TLS payload data.
]]
do
    -- Define the "new" protocol. This is just a pseudo protocol, as we need
    -- to define a new one to invoke it instead of the original one.
    local p_tds_tls = Proto ("tds_tls","TDS TLS Information");

    -- Define our own fields
    local F_tds_stream_firstbyte = ProtoField.uint8("tds.stream.firstbyte", "First byte of the TDS stream/option stream ", base.HEX)
    local F_tds_stream = ProtoField.bytes("tds.stream", "TDS stream/option stream", base.COLON)
    local F_tds_tlspayload = ProtoField.bool("tds.tlspayload", "TDS TLS Payload Present", base.BOOLEAN)

    -- Add the fields to the protocol
    p_tds_tls.fields = {F_tds_stream_firstbyte, F_tds_stream, F_tds_tlspayload}

    -- Declare the fields we need to read from other dissectors
    local f_tcp_payload = Field.new("tcp.payload")
    local f_tds_prelogin = Field.new("tds.prelogin")

    -- Now the dissector itself!
    function p_tds_tls.dissector(tvbuffer, pinfo, treeitem)
        -- we've replaced the TDS dissector in the dissector table,
        -- but we still want it to run, to get all the information it provides,
        -- so we we'll call it manually, before doing our own dissection.
        Dissector.get("tds"):call(tvbuffer, pinfo, treeitem)

        if f_tds_prelogin() then
            -- This is a TDS Prelogin packet, so go ahead...
            local subtreeitem = treeitem:add(p_tds_tls, tvbuffer)
            --infotreeitem = subtreeitem:add("TDS TLS Status Information")

            -- Add value of 9th byte to protocol tree. This is first byte after TDS header, which is always 8 byte long.
            -- We use this byte to establish wheter the TDS packet type is an OPTION packet or a TLS payload packet.
            subtreeitem:add(F_tds_stream_firstbyte, tvbuffer(8,1))

            -- Add TDS stream (or as much as Wireshark can display)
            subtreeitem:add(F_tds_stream, tvbuffer(8))

            -- Store first byte in a variable (easier, looks prettier)
            firstbyte = tvbuffer(8,1):uint()

            -- Check if payload is a TLS content type, indicated by the 
            -- first byte of the TDS stream, following the TDS packet header.
            -- It must not be 0x00 (which is TDS OPTION "VERSION", indicating this is an OPTION prelogin message )
            -- It must be a valid TLS content type as indicated here: https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake
            if firstbyte == 0x14 or firstbyte == 0x15 or firstbyte == 0x16 or firstbyte == 0x17 or firstbyte == 0x18 then
                -- Is TLS payload - call TLS dissector
                subtreeitem:add(F_tds_tlspayload, true):set_text("TDS TLS Payload Present: True")

                Dissector.get("tls"):call(tvbuffer(8):tvb(), pinfo, subtreeitem)
            else
                -- Not TLS payload
                subtreeitem:add(F_tds_tlspayload, false):set_text("TDS TLS Payload Present: False")
            end
        end
    end


    -- Get Wiresharks DissectorTable for tcp, which is based on the TCP port
    -- This table maps which dissectors to invoke, for which ports.
    local tcp_dissector_table = DissectorTable.get("tcp.port")

    -- Now add our new TDS TLS dissector to the table, 
    -- so its invoked for TCP port numbers 1433 and 1521
    tcp_dissector_table:add(1433, p_tds_tls)
    tcp_dissector_table:add(1521, p_tds_tls)
end