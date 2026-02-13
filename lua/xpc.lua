json = require "json/json"

local xpc = Proto("xpc", "XPC")

local f_data      = ProtoField.bytes("xpc.data", "Data")
local f_name      = ProtoField.string("xpc.name", "Service Name")
local f_direction = ProtoField.string("xpc.direction", "Direction")
local f_event     = ProtoField.string("xpc.event", "Event")
local f_peer      = ProtoField.int32("xpc.peer", "Peer PID", base.DEC)
local f_sel       = ProtoField.string("xpc.sel", "Selector")
local f_msgtype   = ProtoField.string("xpc.msgtype", "Message Type")

xpc.fields = { f_data, f_name, f_direction, f_event, f_peer, f_sel, f_msgtype }

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
        parent:add(f_data, data)
    else
        if elem["value"] ~= nil then
            parent:add(tostring(elem["value"]))
        end
    end
end

function xpc.dissector(buffer, pinfo, tree)
    local raw_data_len = pinfo.len - pinfo.caplen
    local breakpoint = buffer:len() - raw_data_len
    local json_range = buffer(0, breakpoint)
    local json_str = json_range:string()
    local data = buffer(breakpoint, raw_data_len)

    local info = json.decode(json_str)
    local root = info["message"]
    local direction = info["direction"] or ""
    local name = info["name"] or "?"
    local peer = info["peer"]
    local event = info["event"] or ""
    local msgtype = root["type"] or "xpc"

    -- filterable metadata
    tree:add(f_direction, json_range, direction)
    tree:add(f_event, json_range, event)
    tree:add(f_name, json_range, name)
    tree:add(f_msgtype, json_range, msgtype)
    if peer then
        tree:add(f_peer, json_range, peer)
    end

    if root["type"] == "nsxpc" then
        local sel = root["sel"] or ""
        tree:add(f_sel, json_range, sel)
        local msg = tree:add("NSXPC: " .. sel)
        local args = root["args"]
        if args then
            local parts = {}
            for part in sel:gmatch("([^:]+)") do
                table.insert(parts, part)
            end
            for i, arg in ipairs(args) do
                local param = parts[i] or tostring(i)
                msg:add(param .. ": " .. tostring(arg))
            end
        end
        pinfo.cols.protocol = "NSXPC"
    else
        local msg = tree:add("Message: " .. desc(root))
        visit(root, msg, data)
        pinfo.cols.protocol = "XPC"
    end

    -- columns
    local label = name
    if peer then
        label = label .. " (" .. tostring(peer) .. ")"
    end

    if direction == ">" then
        pinfo.cols.dst = label
    elseif direction == "<" then
        pinfo.cols.src = label
    end

    pinfo.cols.info = direction .. " " .. desc(root)

    local bt = info["backtrace"]
    if bt then
        local callstack_node = tree:add("Callstack")
        for i, call in ipairs(bt) do
            callstack_node:add(call)
        end
    end
end

frida_log_protocol = Proto("Frida", "Frida Log Protocol")

function frida_log_protocol.dissector(buffer, pinfo, tree)
    local subtree = tree:add(frida_log_protocol, buffer(), "Frida Log Protocol Data")
    xpc.dissector(buffer():tvb(), pinfo, subtree)
end

local wtap_encap = DissectorTable.get("wtap_encap")
wtap_encap:add(wtap.USER0, frida_log_protocol)
