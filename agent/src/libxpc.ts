import ObjC from "frida-objc-bridge";

import { find } from "./symbol.js";
import { bt } from "./utils.js";

const libxpc = Process.findModuleByName("libxpc.dylib");

if (!libxpc) throw new Error("libxpc.dylib not found");

const xpc_connection_create_mach_service = new NativeFunction(
  libxpc.getExportByName("xpc_connection_create_mach_service"),
  "pointer",
  ["pointer", "pointer", "int"],
);
const xpc_connection_set_event_handler = new NativeFunction(
  libxpc.getExportByName("xpc_connection_set_event_handler"),
  "void",
  ["pointer", "pointer"],
);
const xpc_connection_resume = new NativeFunction(
  libxpc.getExportByName("xpc_connection_resume"),
  "void",
  ["pointer"],
);

// connection info
const xpc_connection_get_name = new NativeFunction(
  libxpc.getExportByName("xpc_connection_get_name"),
  "pointer",
  ["pointer"],
);
const xpc_connection_get_pid = new NativeFunction(
  libxpc.getExportByName("xpc_connection_get_pid"),
  "int",
  ["pointer"],
);

const xpc_copy_description = new NativeFunction(
  libxpc.getExportByName("xpc_copy_description"),
  "pointer",
  ["pointer"],
);
const xpc_get_type = new NativeFunction(
  libxpc.getExportByName("xpc_get_type"),
  "pointer",
  ["pointer"],
);

// buffer types
const xpc_string_get_string_ptr = new NativeFunction(
  libxpc.getExportByName("xpc_string_get_string_ptr"),
  "pointer",
  ["pointer"],
);
const xpc_string_get_length = new NativeFunction(
  libxpc.getExportByName("xpc_string_get_length"),
  "size_t",
  ["pointer"],
);
const xpc_data_get_bytes_ptr = new NativeFunction(
  libxpc.getExportByName("xpc_data_get_bytes_ptr"),
  "pointer",
  ["pointer"],
);
const xpc_data_get_length = new NativeFunction(
  libxpc.getExportByName("xpc_data_get_length"),
  "size_t",
  ["pointer"],
);
const xpc_uuid_get_bytes = new NativeFunction(
  libxpc.getExportByName("xpc_uuid_get_bytes"),
  "pointer",
  ["pointer"],
);

// primitive types
const xpc_double_get_value = new NativeFunction(
  libxpc.getExportByName("xpc_double_get_value"),
  "double",
  ["pointer"],
);
const xpc_bool_get_value = new NativeFunction(
  libxpc.getExportByName("xpc_bool_get_value"),
  "bool",
  ["pointer"],
);
const xpc_int64_get_value = new NativeFunction(
  libxpc.getExportByName("xpc_int64_get_value"),
  "int64",
  ["pointer"],
);
const xpc_uint64_get_value = new NativeFunction(
  libxpc.getExportByName("xpc_uint64_get_value"),
  "uint64",
  ["pointer"],
);

// apply functions
const xpc_dictionary_apply = new NativeFunction(
  libxpc.getExportByName("xpc_dictionary_apply"),
  "bool",
  ["pointer", "pointer"],
);
const xpc_array_apply = new NativeFunction(
  libxpc.getExportByName("xpc_array_apply"),
  "bool",
  ["pointer", "pointer"],
);

// remote resources
const xpc_fd_dup = new NativeFunction(
  libxpc.getExportByName("xpc_fd_dup"),
  "int",
  ["pointer"],
);

const xpcTypes = libxpc
  .enumerateExports()
  .filter((s) => s.name.startsWith("_xpc_type_"));
const xpcDictionaryType = xpcTypes.find(
  (s) => s.name === "_xpc_type_dictionary",
)!.address;
const xpcArrayType = xpcTypes.find(
  (s) => s.name === "_xpc_type_array",
)!.address;

const fcntl = new NativeFunction(Module.getGlobalExportByName("fcntl"), "int", [
  "int",
  "int",
  "pointer",
]);
const free = new NativeFunction(Module.getGlobalExportByName("free"), "void", [
  "pointer",
]);

function copyDescription(obj: NativePointer) {
  const desc = xpc_copy_description(obj);
  const str = desc.readUtf8String();
  free(desc);
  return str;
}

interface XPCNode {
  description: string;
  type: string;
}

interface XPCConnection extends XPCNode {
  name: string;
  pid: number;
}

interface XPCString extends XPCNode {
  value: string;
}

interface XPCDictionary extends XPCNode {
  keys: string[];
  values: XPCNode[];
}

interface XPCArray extends XPCNode {
  values: XPCNode[];
}

interface XPCUUID extends XPCNode {
  offset: number;
  value: string;
}

interface XPCDouble extends XPCNode {
  value: number;
}

interface XPCBoolean extends XPCNode {
  value: boolean;
}

interface XPCFileDescriptor extends XPCNode {
  value: number;
  path: string; // fcntl(fd, F_GETPATH, ...)
}

interface XPCUInt64 extends XPCNode {
  value: string;
}

type XPCInt64 = XPCUInt64;

interface XPCData extends XPCNode {
  offset: number;
  length: number;
}

interface Message {
  source: [string, number] /* name, pid */;
  destination: [string, number] /* name, pid */;
  type: "nsxpc" | "xpc";
  description: string;
  root: XPCNode;
}

/**
 * @class LogSerializer
 * @description Serialize XPC messages into JSON and send them to the server.
 */
class LogSerializer {
  #dataBuffers: ArrayBuffer[] = [];
  #offset = 0;

  constructor(private readonly root: NativePointer) {}

  serialize(): [XPCNode, ArrayBuffer] {
    const json = this.dump(this.root);
    const joint = new Uint8Array(this.#offset);

    for (let i = 0, offset = 0; i < this.#dataBuffers.length; i++) {
      const buf = this.#dataBuffers[i];
      joint.set(new Uint8Array(buf), offset);
      offset += buf.byteLength;
    }

    return [json, joint.buffer as ArrayBuffer];
  }

  private appendData(data: ArrayBuffer) {
    const offset = this.#offset;
    this.#dataBuffers.push(data);
    this.#offset += data.byteLength;
    return offset;
  }

  private dump(xpcObj: NativePointer) {
    const self = this;
    const t = xpc_get_type(xpcObj);
    const description = copyDescription(xpcObj);

    if (t.equals(xpcDictionaryType)) {
      // dictionary?
      const keys: string[] = [];
      const values: XPCNode[] = [];

      xpc_dictionary_apply(
        xpcObj,
        new ObjC.Block({
          retType: "bool",
          argTypes: ["pointer", "pointer"],
          implementation(key: NativePointer, value: NativePointer) {
            keys.push(key.readUtf8String()!);
            values.push(self.dump(value));
            return true;
          },
        }),
      );

      return { description, keys, values, type: "dictionary" } as XPCDictionary;
    }

    if (t.equals(xpcArrayType)) {
      // array?
      const values: XPCNode[] = [];
      xpc_array_apply(
        xpcObj,
        new ObjC.Block({
          retType: "bool",
          argTypes: ["uint64", "pointer"],
          implementation(index, value) {
            values.push(self.dump(value));
            return true;
          },
        }),
      );

      return { description, values, type: "array" } as XPCArray;
    }

    for (const xpcType of xpcTypes) {
      if (xpc_get_type(xpcObj).equals(xpcType.address)) {
        const type = xpcType.name.replace(/^_xpc_type_/, "");

        if (type === "string") {
          const value = xpc_string_get_string_ptr(xpcObj).readUtf8String(
            xpc_string_get_length(xpcObj).toNumber(),
          );
          return { description, value, type } as XPCString;
        } else if (type === "data") {
          const base = xpc_data_get_bytes_ptr(xpcObj);
          const length = xpc_data_get_length(xpcObj).toNumber();
          const data = base.readByteArray(length)!;
          const offset = this.appendData(data);
          return { description, type, offset, length, base } as XPCData;
        } else if (type === "uuid") {
          const p = xpc_uuid_get_bytes(xpcObj);
          const data = p.readByteArray(16)!;
          const offset = this.appendData(data);
          const value = [...new Uint8Array(data)]
            .map((x) => x.toString(16).padStart(2, "0"))
            .join("");

          return { description, type, offset, value } as XPCUUID;
        } else if (type === "double") {
          const value = xpc_double_get_value(xpcObj);
          return { description, type, value } as XPCDouble;
        } else if (type == "uint64") {
          const value = xpc_uint64_get_value(xpcObj).toString();
          return { description, type, value } as XPCUInt64;
        } else if (type == "int64") {
          const value = xpc_int64_get_value(xpcObj).toString();
          return { description, type, value } as XPCInt64;
        } else if (type === "bool") {
          const value = xpc_bool_get_value(xpcObj) !== 0;
          return { description, type, value } as XPCBoolean;
        } else if (type === "fd") {
          const F_GETPATH = 50;
          const MAXPATHLEN = 1024;
          const buf = Memory.alloc(MAXPATHLEN);
          const value = xpc_fd_dup(xpcObj);
          const rc = fcntl(value, F_GETPATH, buf);

          if (rc === 0) {
            const path = buf.readUtf8String();
            return { description, type, value, path } as XPCFileDescriptor;
          }

          // can not get path, fallback to default strucutre
        }

        // todo: more types
        return { description, type } as XPCNode;
      }
    }

    throw new Error("unknown xpc type");
  }
}

export async function start() {
  const dispacher = find("libxpc.dylib", "_xpc_connection_call_event_handler");

  Interceptor.attach(dispacher, {
    onEnter(args) {
      const conn = args[0];
      const msg = args[1];

      if (!xpc_get_type(msg).equals(xpcDictionaryType)) return;

      const name = xpc_connection_get_name(conn).readUtf8String();
      const pid = xpc_connection_get_pid(conn);

      // console.log(name, pid, '->', Process.id, Process.mainModule.name);

      const serializer = new LogSerializer(msg);
      // console.log(copyDescription(conn));

      const [json, data] = serializer.serialize();
      // console.log(JSON.stringify(json, null, 2));
      // console.log(copyDescription(msg));

      send(
        {
          event: "received",
          name,
          peer: pid,
          direction: "<",
          message: json,
        },
        data,
      );
    },
  });

  for (const suffix of ["", "_with_reply", "_with_reply_sync"]) {
    const name = `xpc_connection_send_message${suffix}`;
    const func = libxpc!.getExportByName(name);
    if (!func) throw new Error(`symbol ${name} not found`);

    Interceptor.attach(func, {
      onEnter(args) {
        const conn = args[0];
        const msg = args[1];

        const name = xpc_connection_get_name(conn).readUtf8String();
        const pid = xpc_connection_get_pid(conn);

        const serializer = new LogSerializer(msg);
        const [json, data] = serializer.serialize();

        const backtrace = bt(this.context);

        send(
          {
            event: "sent",
            name,
            peer: pid,
            direction: ">",
            message: json,
            data,
            backtrace,
          },
          data,
        );
      },
    });
  }
}
