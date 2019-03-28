-- Declare the protocol
udp_server_proto = Proto("udp_server", "UDP Server Assignment Protocol")
-- Create a dissector callback
function udp_server_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("UDP-Server")
    local subtree = tree:add(udp_server_proto, buffer(), "UDP Server")
    buflen = buffer:reported_length_remaining()
    if buflen == 19 then
        pinfo.cols.info:set("TimeRequest")
        -- ver 1 byte
        -- seq 2 byte
        -- cli sec 8 bytes
        -- cli nsec 8 bytes
        subtree:add(buffer(0,1), "Version: " .. buffer(0,1):uint())
        subtree:add(buffer(1,2), "Sequence: " .. buffer(1,2):uint())
        subtree:add(buffer(3,8), "Client seconds: " .. buffer(3,8):uint64())
        subtree:add(buffer(11,8), "Client nanoseconds: " .. buffer(11,8):uint64())
    elseif buflen == 35 then
        pinfo.cols.info:set("TimeResponse")
        -- ver 1 byte
        -- seq 2 bytes
        -- cli sec 8 bytes
        -- cli nsec 8 bytes
        -- srv sec 8 bytes
        -- srv nsec 8 bytes
        subtree:add(buffer(0,1), "Version: " .. buffer(0,1):uint())
        subtree:add(buffer(1,2), "Sequence: " .. buffer(1,2):uint())
        subtree:add(buffer(3,8), "Client seconds: " .. buffer(3,8):uint64())
        subtree:add(buffer(11,8), "Client nanoseconds: " .. buffer(11,8):uint64())
        subtree:add(buffer(19,8), "Server seconds: " .. buffer(19,8):uint64())
        subtree:add(buffer(27,8), "Server nanoseconds: " .. buffer(27,8):uint64())
    end
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(7777, udp_server_proto)
