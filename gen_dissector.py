#!/usr/bin/env python3

'''
This script generates a Wireshark Lua dissector script when given an
appropriate YAML file describing a protocol format.
Author: Vikram Rao
'''

import sys
import yaml


# needs the protocol name "proto", the header parsers "headerparsers",
# the message parsers "messageparsers", and the protocol field adders "protofields"
TCP_skeleton_dissector ='''\
-- Declare the protocol
{proto}_proto = Proto("{proto}", "{proto}")

-- Add protocol fields
{protofields}

-- Create a callback for our dissector
function {proto}_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("{proto}")
    local pktlen = buffer:len()
    local bytes_consumed = 0

    while bytes_consumed < pktlen do
        local result = dissect_{proto}(buffer, pinfo, tree, bytes_consumed)
        if result > 0 then
            -- We successfully processed a complete message
            bytes_consumed = bytes_consumed + result
        elseif result == 0 then
            -- We hit an error of some kind
            -- Return 0, tell Wireshark to try another protocol
            return 0
        else
            -- We need 'result' more bytes to finish parsing the current message
            pinfo.desegment_offset = bytes_consumed
            pinfo.desegment_len = -result
            -- Return pktlen, tell Wireshark we were able to successfully parse all
            -- the data so far
            return pktlen
        end
    end
    -- Return pktlen, tell Wireshark we were able to successfully parse all the data
    return pktlen
end

function dissect_{proto}(buffer, pinfo, tree, offset)
    local end_ind = buffer:len()
    -- Detect packet data being cut off during capture
    if end_ind - offset ~= buffer:reported_length_remaining(offset) then
        return 0
    end

    -- Keep track of our current position in the packet
    local curr_pos = offset

    -- Parse headers
{headerparsers}

    local message_pos = curr_pos

    -- Parse different message types
{messageparsers}
    
    return curr_pos - offset
end

-- Register the protocol
{proto}_table = DissectorTable.get("tcp.port")
{proto}_table:add(41714, {proto}_proto)
'''
# needs the field name "name", the field length "length", and the
# value formatter (uint(), uint64(), bytes(), etc.) "formatter"
TCP_skeleton_fieldparser = '''local len_{name} = {length}
if end_ind < curr_pos + len_{name} then
    -- Unknown number of bytes still needed
    return -DESEGMENT_ONE_MORE_SEGMENT
end
local {name}_buf = buffer(curr_pos, len_{name})
local {name} = {name}_buf:{formatter}
curr_pos = curr_pos + len_{name}'''


# needs the protocol name "proto", the header parsers "headerparsers",
# the message parsers "message parsers"
UDP_skeleton_dissector ='''\
-- Declare the protocol
{proto}_proto = Proto("{proto}", "{proto}")

-- Add protocol fields
{protofields}

-- Create a callback for our dissector
function {proto}_proto.dissector(buffer, pinfo, tree)

    -- Label the protocol column with our protocol name
    pinfo.cols.protocol:set("{proto}")
    -- Get the total packet length
    local PacketLength = buffer:reported_length_remaining()

    -- Parser
    -- Keep track of our current position in the packet
    local curr_pos = 0

    -- Parse headers
{headerparsers}

    local message_pos = curr_pos

    -- Parse different message types
{messageparsers}

    return curr_pos
end

-- Register the protocol
{proto}_table = DissectorTable.get("udp.port")
{proto}_table:add(41714, {proto}_proto)
'''
# needs the field name "name", the field length "length", and the
# value formatter (uint(), uint64(), bytes(), etc.) "formatter"
UDP_skeleton_fieldparser = '''local len_{name} = {length}
if PacketLength < curr_pos + len_{name} then
    -- Not a match for our protocol
    return 0
end
local {name}_buf = buffer(curr_pos, len_{name})
local {name} = {name}_buf:{formatter}
curr_pos = curr_pos + len_{name}'''



''' Print the error message to stderr and exit '''
def fail(err):
    sys.stderr.write('Error: ' + str(err) + '\n')
    sys.exit(-1)


''' Print a warning message '''
def warn(warning):
    sys.stderr.write('Warning: ' + str(warning) + '\n')


''' Indent the given lines '''
def indent(text, num_indent=1):
    indented = '\n'.join(('    '*num_indent + line) for line in text.split('\n'))
    return indented


''' Validate specified field datatypes and length '''
def preprocess_dtypes(proto):
    for field in proto['header_fields']:
        if field['type'] == 'int':
            if field['length'] in (1,2,3,4):
                field['wtype'] = 'uint' + str(field['length'] * 8)
                field['formatter'] = 'uint()'
            elif field['length'] in (5,6,7,8):
                warn(str(field['name']) + ' being parsed to UInt64, cannot be used as an index')
                field['wtype'] = 'uint64'
                field['formatter'] = 'uint64()'
            else:
                fail(str(field['name']) + ' cannot be safely parsed into any wireshark integer datatypes')
            # handle little-endian ints in protocol
            if 'le' in field and field['le']:
                field['formatter'] = 'le_' + field['formatter']
        elif field['type'] == 'data':
            field['wtype'] = 'string'
            field['formatter'] = 'string()'
        else:
            fail(str(field['name']) + ' does not have a valid type')
    for mname,mproto in proto['message_types'].items():
        for field in mproto['fields']:
            if field['type'] == 'int':
                if field['length'] in (1,2,3,4):
                    field['wtype'] = 'uint' + str(field['length'] * 8)
                    field['formatter'] = 'uint()'
                elif field['length'] in (5,6,7,8):
                    warn(str(field['name']) + ' being parsed to UInt64, cannot be used as an index')
                    field['wtype'] = 'uint64'
                    field['formatter'] = 'uint64()'
                else:
                    fail(str(field['name']) + ' cannot be safely parsed into any wireshark integer datatypes')
                # handle little-endian ints in protocol
                if 'le' in field and field['le']:
                    field['formatter'] = 'le_' + field['formatter']
            elif field['type'] == 'data':
                field['wtype'] = 'string'
                field['formatter'] = 'string()'
            else:
                fail(str(field['name']) + ' does not have a valid type')


'''
Generate Lua code to add protocol fields which you can filter by in
the search bar, e.g. when you filter by tcp or tcp.len > 0.
'''
def gen_protocolfields(proto):
    # the protocol field names to be registered with the protocol
    fieldnames = []
    # the lua code to add the protocol fields
    fieldadders = []

    # gen lua code to add the header fields as protofields
    for field in proto['header_fields']:
        fieldnames.append('pf_{name}'.format(name=field['name']))
        fieldadders.append('local pf_{name} = ProtoField.{wtype}("{proto}.{name}")'.format(name=field['name'],wtype=field['wtype'],proto=proto['name']))

    # gen lua code to add the message types and fields as protofields
    for mname,mproto in proto['message_types'].items():
        # message type
        fieldnames.append('pf_{mname}'.format(mname=mname))
        fieldadders.append('local pf_{mname} = ProtoField.protocol("{proto}.{mname}")'.format(mname=mname,proto=proto['name']))
        # message fields
        for field in mproto['fields']:
            fieldnames.append('pf_{mname}_{name}'.format(mname=mname,name=field['name']))
            fieldadders.append('local pf_{mname}_{name} = ProtoField.{wtype}("{proto}.{mname}.{name}")'.format(mname=mname,name=field['name'],wtype=field['wtype'],proto=proto['name']))
    # register all the protofields
    register_code = '{proto}_proto.fields = {{{protofieldnames}}}'.format(proto=proto['name'],protofieldnames=', '.join(fieldnames))
    return '\n'.join(fieldadders) + '\n' + register_code


''' Generate Lua code to parse all message types '''
def gen_message_parsers(proto, fieldparser_skeleton):
    messageparsers = []
    # all conditions after the first need an "elseif", not just "if"
    first_message = True
    for mname,mproto in proto['message_types'].items():
        # the condition guarding this message type
        condition = 'if {condition} then'.format(condition=mproto['condition'])
        if not first_message:
            condition = 'else' + condition
        first_message = False
        messageparsers.append(condition)
        # the actual message parsing + tree building
        messageparsers.append(indent('-- Parse fields specific to this message type'))
        singlemessage_parser = gen_fieldparsers(mproto['fields'], fieldparser_skeleton)
        messageparsers.append(indent(singlemessage_parser))
        singlemessage_treebuilder = gen_singlemessage_treebuilder(proto, mname, mproto)
        messageparsers.append(indent(singlemessage_treebuilder))
    # if there are any message parsers, we add an else block in case none of them match
    if messageparsers:
        messageparsers += ['else', indent('return 0'), 'end']
    return '\n'.join(messageparsers)


''' Generate Lua code to parse a list of fields '''
def gen_fieldparsers(fields, fieldparser_skeleton):
    # a skeleton assertions about a field's value
    skeleton_fieldassertion = '''-- Assert that the value matches what we expect
    if {name} ~= {value} then
        return 0
    end'''
    # generate parsers for all given fields
    parsers = []
    for field in fields:
        fieldparser = fieldparser_skeleton.format(name=field['name'],
                length=field['length'], formatter=field['formatter'])
        # if the field has a constant value, assert that in Lua
        if 'value' in field:
            if field['type'] == 'int':
                assertionvalue = field['value']
            else:
                assertionvalue = '"' + field['value'] + '"'
            fieldparser += '\n' + skeleton_fieldassertion.format(name=field['name'],value=assertionvalue)
        parsers.append(fieldparser)
    parsers = '\n'.join(parsers)
    return parsers


''' Generate Lua code to build the tree for a specific message type '''
def gen_singlemessage_treebuilder(proto, mname, mproto):
    # Set the info field to the message type
    setinfo =  'if string.find(tostring(pinfo.cols.info), "^{proto}") == nil then'.format(proto=proto['name'])
    setinfo += indent('pinfo.cols.info:set("{proto}: {mname}")'.format(proto=proto['name'],mname=mname))
    setinfo += 'else'
    setinfo += indent('pinfo.cols.info:append(", {mname}")'.format(mname=mname))
    setinfo += 'end'
    # Create subtree in the dissector view for this protocol
    subtree = []
    subtree.append('-- Create a subtree in the Wireshark dissector view')
    subtree.append('local subtree = tree:add({proto}_proto, buffer(0,curr_pos), "{proto}")'.format(proto=proto['name']))
    # Header fields have simple protocol field names
    for field in proto['header_fields']:
        if field['type'] == 'data':
            # Due to issues with data decoding correctly, just give an empty value
            subtree.append(indent('subtree:add(pf_{name}, {name}_buf, tostring({name}))'.format(name=field['name'])))
        else:
            subtree.append('subtree:add(pf_{name}, {name}_buf, {name})'.format(name=field['name']))
    # Add new subtree for message type
    subtree.append('local msgtree = subtree:add(pf_{mname}, buffer(message_pos, curr_pos - message_pos))'.format(mname=mname))
    # Message-specific fields have the message name as part of their field name
    for field in mproto['fields']:
        if field['type'] == 'data':
            subtree.append('msgtree:add(pf_{mname}_{name}, {name}_buf, tostring({name}))'.format(name=field['name'],mname=mname))
        else:
            subtree.append('msgtree:add(pf_{mname}_{name}, {name}_buf, {name})'.format(name=field['name'],mname=mname))
    return setinfo + '\n' + '\n'.join(subtree)


''' Generate a Wireshark Lua plugin to dissect packets of this TCP protocol '''
def gen_dissector_TCP(proto):
    # Generate code to add protocol fields as filters
    protofieldadders = gen_protocolfields(proto)

    # Generate code to parse header fields
    headerparsers = gen_fieldparsers(proto['header_fields'], TCP_skeleton_fieldparser)

    # Generate code to parse message fields
    messageparsers = gen_message_parsers(proto, TCP_skeleton_fieldparser)

    # Fill the parser into the dissector
    dissector = TCP_skeleton_dissector.format(proto=proto['name'], protofields=protofieldadders,
            headerparsers=indent(headerparsers), messageparsers=indent(messageparsers))

    return dissector


''' Generate a Wireshark Lua plugin to dissect packets of this UDP protocol '''
def gen_dissector_UDP(proto):
    # Generate code to add protocol fields as filters
    protofieldadders = gen_protocolfields(proto)

    # Generate code to parse header fields
    headerparsers = gen_fieldparsers(proto['header_fields'], UDP_skeleton_fieldparser)

    # Generate code to parse message fields
    messageparsers = gen_message_parsers(proto, UDP_skeleton_fieldparser)

    # Fill the parser into the dissector
    dissector = UDP_skeleton_dissector.format(proto=proto['name'], protofields=protofieldadders,
            headerparsers=indent(headerparsers), messageparsers=indent(messageparsers))

    return dissector


if __name__ == '__main__':
    if len(sys.argv) < 3:
        fail('Usage: gen_dissector protocol_file.json outfile')

    proto_file = sys.argv[1]
    outfile = sys.argv[2]
    with open(proto_file) as f:
        proto = yaml.safe_load(f)

    preprocess_dtypes(proto)

    if proto['transport'] == 'UDP':
        dissector = gen_dissector_UDP(proto)
    elif proto['transport'] == 'TCP':
        dissector = gen_dissector_TCP(proto)
    else:
        fail('Invalid transport protocol.')

    out = open(outfile, 'w')
    out.write(dissector)
    out.close()
    print('Successfully generated dissector.')

