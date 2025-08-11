json = require "json.lua"

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
        if elem["value"] then
            parent:add(elem["value"])
        end
    end
end

function xpc.dissector(buffer, pinfo, tree)
    local data = buffer(pinfo.len)
    local info = json.decode(buffer(0, pinfo.caplen - pinfo.len):string())
    local root = info["message"]
    local msg = tree:add("Message" .. ": " .. desc(root))
    visit(root, msg, data)

    local bt = info["backtrace"]
    if bt then
        local callstack_node = tree:add("Callstack")
        for i, call in ipairs(bt) do
            callstack_node:add(call)
        end
    end
end
