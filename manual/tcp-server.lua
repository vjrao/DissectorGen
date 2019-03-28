-- Declare the protocol
tcp_server_proto = Proto("tcp_server", "tcp_server Assignment Protocol")
-- Create a dissector callback
function tcp_server_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("TCP_SERVER")
    local pktlen = buffer:len()
    local bytes_consumed = 0

    while bytes_consumed < pktlen do
        local result = dissect_tcp_server(buffer, pinfo, tree, bytes_consumed)
        io.stderr:write(result .. ' ')
        if result > 0 then
            -- We successfully processed a complete message
            bytes_consumed = bytes_consumed + result
        elseif result == 0 then
            -- We hit an error of some kind
            -- Return 0, tell Wireshark to let some other proto try to parse
            return 0
        else
            -- We need "result" more bytes to finish parsing
            pinfo.desegment_offset = bytes_consumed
            pinfo.desegment_len = -result
            -- Return pktlen, tell Wireshark we were able to successfully
            -- parse this data
            return pktlen
        end
    end
    -- Return pktlen, tell Wireshark we were able to successfully parse all
    -- this data
    return pktlen
end

function dissect_tcp_server(buffer, pinfo, tree, offset)
    local remlen = buffer:len() - offset
    -- Detect packet data being cut off
    if remlen ~= buffer:reported_length_remaining(offset) then
        return 0
    end

    local len_MessageType = 2
    if remlen < len_MessageType then
        -- Unknown number of bytes still needed
        return -DESEGMENT_ONE_MORE_SEGMENT
    end
    -- We have the message type
    local MessageType_buf = buffer(offset,len_MessageType)
    local MessageType = MessageType_buf:uint()
    if MessageType == 1 then
        -- Initialization
        local len_N = 4
        -- Check if we have the full message
        local TotalLen = len_MessageType + len_N
        if remlen < TotalLen then
            return -(TotalLen - remlen)
        end
        -- Parse
        local N_buf = buffer(offset+len_MessageType,len_N)
        local N = N_buf:uint()
        -- Add to the parse tree
        local subtree = tree:add(tcp_server_proto, buffer(offset, TotalLen), "TCP_SERVER")
        subtree:add(MessageType_buf, "MessageType", MessageType)
        subtree:add(N_buf, "N", N)
        -- Update the columns
        if string.find(tostring(pinfo.cols.info), "^TCP_SERVER") == nil then
            pinfo.cols.info:set("TCP_SERVER: Initialization")
        else
            pinfo.cols.info:append(", Initialization")
        end
        -- Return the number of bytes consumed
        return TotalLen
    elseif MessageType == 2 then
        -- Acknowledgement
        local len_HashResponsesLength = 4
        -- Check if we have the full message
        local TotalLen = len_MessageType + len_HashResponsesLength
        if remlen < TotalLen then
            return -(TotalLen - remlen)
        end
        -- Parse
        local HashResponsesLength_buf = buffer(offset+len_MessageType,len_HashResponsesLength)
        local HashResponsesLength = HashResponsesLength_buf:uint()
        -- Add to the parse tree
        local subtree = tree:add(tcp_server_proto, buffer(offset, TotalLen), "TCP_SERVER")
        subtree:add(MessageType_buf, "MessageType", MessageType)
        subtree:add(HashResponsesLength_buf, "HashResponsesLength", HashResponsesLength)
        -- Update the columns
        if string.find(tostring(pinfo.cols.info), "^TCP_SERVER") == nil then
            pinfo.cols.info:set("TCP_SERVER: Acknowledgement")
        else
            pinfo.cols.info:append(", Acknowledgement")
        end
        -- Return the number of bytes consumed
        return TotalLen
    elseif MessageType == 3 then
        -- HashRequest
        local len_DataLength = 4
        local TotalLen = len_MessageType + len_DataLength
        if remlen < TotalLen then
            return -DESEGMENT_ONE_MORE_SEGMENT
        end
        local DataLength_buf = buffer(offset+len_MessageType, len_DataLength)
        local DataLength = DataLength_buf:uint()
        TotalLen = TotalLen + DataLength
        if remlen < TotalLen then
            return -DESEGMENT_ONE_MORE_SEGMENT
        end
        local Data_buf = buffer(offset+len_MessageType+len_DataLength, DataLength)
        local Data = Data_buf:bytes()
        -- Add to the parse tree
        local subtree = tree:add(tcp_server_proto, buffer(offset, TotalLen), "TCP_SERVER")
        subtree:add(MessageType_buf, "MessageType", MessageType)
        subtree:add(DataLength_buf, "DataLength", DataLength)
        subtree:add(Data_buf, "Data", Data)
        -- Update the columns
        if string.find(tostring(pinfo.cols.info), "^TCP_SERVER") == nil then
            pinfo.cols.info:set("TCP_SERVER: HashRequest")
        else
            pinfo.cols.info:append(", HashRequest")
        end
        -- Return the number of bytes consumed
        return TotalLen
    elseif MessageType == 4 then
        -- HashResponse
        local len_i = 4
        local len_Hash = 32
        -- Check if we have the full message
        local TotalLen = len_MessageType + len_i
        if remlen < TotalLen then
            return -DESEGMENT_ONE_MORE_SEGMENT
        end
        TotalLen = TotalLen + len_Hash
        if remlen < TotalLen then
            return -(TotalLen - remlen)
        end
        -- Parse
        local i_buf = buffer(offset+len_MessageType, len_i)
        local i = i_buf:uint()
        local Hash_buf = buffer(offset+len_MessageType+len_i, len_Hash)
        local Hash = Hash_buf:bytes()
        -- Add to the parse tree
        local subtree = tree:add(tcp_server_proto, buffer(offset, TotalLen), "TCP_SERVER")
        subtree:add(MessageType_buf, "MessageType", MessageType)
        subtree:add(i_buf, "i", i)
        subtree:add(Hash_buf, "Hash", Hash)
        -- Update the columns
        if string.find(tostring(pinfo.cols.info), "^TCP_SERVER") == nil then
            pinfo.cols.info:set("TCP_SERVER: HashResponse")
        else
            pinfo.cols.info:append(", HashResponse")
        end
        -- Return the number of bytes consumed
        return TotalLen
    else
        -- Invalid message type, probably wrong protocol
        return 0
    end
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(7777, tcp_server_proto)
