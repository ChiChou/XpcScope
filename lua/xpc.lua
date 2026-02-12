json = require "json/json"

local xpc = Proto("xpc", "XPC")
local binary = ProtoField.bytes("xpc.data", "xpc_data")

xpc.fields = { binary }

function desc(node)
    local description = node["description"]
    local stop = string.find(description, ">")
    if stop then
        return string.sub(description, 0, stop)
    else
        return description
    end
end

function visit(elem, parent, data_storage)
    if elem["type"] == "dictionary" then
        local keys = elem["keys"]
        local values = elem["values"]

        for i, key in ipairs(keys) do
            local value = values[i]
            visit(value, parent:add(key .. ": " .. desc(value)), data_storage)
        end
    elseif elem["type"] == "array" then
        local values = elem["values"]

        for i, value in ipairs(values) do
            visit(value, parent:add("[" .. i .. "]: " .. desc(value)), data_storage)
        end
    elseif elem["type"] == "data" then
        local offset = elem["offset"]
        local length = elem["length"]
        local data = data_storage(offset, length)
        parent:add(binary, data)
    else
        if elem["value"] ~= nil then
            parent:add(tostring(elem["value"]))
        end
    end
end

function xpc.dissector(buffer, pinfo, tree)
    local raw_data_len = pinfo.len - pinfo.caplen
    local breakpoint = buffer:len() - raw_data_len
    local json_str = buffer(0, breakpoint):string()
    local data = buffer(breakpoint, raw_data_len)

    local info = json.decode(json_str)
    local root = info["message"]
    local msg = tree:add("Message" .. ": " .. desc(root))
    visit(root, msg, data)

    pinfo.cols.protocol = "XPC"

    local direction = info["direction"] or ""
    local name = info["name"] or ""
    local peer = info["peer"] or ""
    pinfo.cols.info = direction .. " " .. name .. " (pid " .. tostring(peer) .. ") " .. desc(root)

    local bt = info["backtrace"]
    if bt then
        local callstack_node = tree:add("Callstack")
        for i, call in ipairs(bt) do
            callstack_node:add(call)
        end
    end
end

local source_pid          = ProtoField.int32("xpc.sourcepid", "Source PID", base.DEC)
local dest_pid            = ProtoField.int32("xpc.destpid", "Destination PID", base.DEC)

frida_log_protocol        = Proto("Frida", "Frida Log Protocol")
frida_log_protocol.fields = {
    source_pid, dest_pid
}

function frida_log_protocol.dissector(buffer, pinfo, tree)
    pinfo.src = Address.ip('127.0.0.1')
    pinfo.dst = Address.ip('127.0.0.1')

    local subtree = tree:add(frida_log_protocol, buffer(), "Frida Log Protocol Data")
    xpc.dissector(buffer():tvb(), pinfo, subtree)
end

local tcp_port = DissectorTable.get("ethertype")
tcp_port:add(0x807, frida_log_protocol)
