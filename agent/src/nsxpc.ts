import ObjC from "frida-objc-bridge";
import { find, glob } from "./symbol.js";
import { bt } from "./utils.js";

// make sure the Foundation.framework is loaded
ObjC.classes.NSBundle.bundleWithPath_(
  "/System/Library/Frameworks/Foundation.framework",
).load();

const { NSXPCListener } = ObjC.classes;

function formatArgs(
  args: InvocationArguments,
  signature: ObjC.Object,
): string[] {
  const nargs = signature.numberOfArguments();
  const result: string[] = [];
  for (let i = 2; i < nargs; i++) {
    const arg = args[i];
    const t = signature.getArgumentTypeAtIndex_(i);
    const wrapped = t.toString().startsWith("@") ? new ObjC.Object(arg) : arg;
    result.push(wrapped.toString());
  }
  return result;
}

function formatDescription(
  self: NativePointer,
  clazz: string,
  sel: string,
  args: InvocationArguments,
): string {
  const parts = sel.split(":");
  const nparams = sel.includes(":") ? parts.length - 1 : 0;

  function* gen() {
    yield `<${clazz} ${self}>`;
    if (nparams === 0) {
      yield ` ${sel}`;
      return;
    }
    for (let i = 0; i < nparams; i++) {
      if (i === 0) yield " ";
      yield `${parts[i] || ""}:${args[i + 2]}`;
    }
  }

  return [...gen()].join("");
}

export function listeners() {
  return ObjC.chooseSync(NSXPCListener).map((listener) => {
    return {
      delegate: listener.delegate()?.$className,
      serviceName: listener.serviceName()?.toString(),
    };
  });
}

export function start() {
  const invoker = find(
    "Foundation",
    "__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT__",
  ).strip();

  Interceptor.attach(invoker, {
    onEnter(args) {
      const invocation = new ObjC.Object(args[0]);
      const target = invocation.target();
      const selector = invocation.selector();
      const sel = ObjC.selectorAsString(selector);

      const imp = target.methodForSelector_(selector).strip() as NativePointer;
      const signature = target.methodSignatureForSelector_(
        selector,
      ) as ObjC.Object;

      this.hook = Interceptor.attach(imp, {
        onEnter(innerArgs) {
          const json = {
            type: "nsxpc",
            sel,
            args: formatArgs(innerArgs, signature),
            description: formatDescription(
              innerArgs[0],
              target.$className,
              sel,
              innerArgs,
            ),
          };

          send({
            event: "received",
            // name,
            // peer: pid,
            direction: "<",
            message: json,
          });
        },
      });
    },
    onLeave() {
      this.hook.detach();
    },
  });

  for (const func of glob(
    "Foundation",
    "__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT_S*",
  )) {
    const plain = func.strip();

    Interceptor.attach(plain, {
      onEnter(args) {
        const targetClass = new ObjC.Object(args[0]);
        const sel = ObjC.selectorAsString(args[1]);
        const signature = targetClass.methodSignatureForSelector_(args[1]);

        const json = {
          type: "nsxpc",
          sel,
          args: formatArgs(args, signature),
          description: formatDescription(
            args[0],
            targetClass.$className,
            sel,
            args,
          ),
        };

        send({
          event: "received",
          // name,
          // peer: pid,
          direction: "<",
          message: json,
        });
      },
    });
  }

  for (const sel in ObjC.protocols.NSXPCProxyCreating.methods) {
    Interceptor.attach(ObjC.classes.NSXPCConnection[sel].implementation, {
      onEnter(args) {
        this.conn = args[0];
      },
      onLeave(retValue) {
        ObjC.bind(retValue, { conn: this.conn });
      },
    });
  }

  const senders = glob("Foundation", "_NSXPCDistantObjectSimpleMessageSend*");
  for (const func of senders) {
    const { name } = DebugSymbol.fromAddress(func);
    if (!name) continue;

    Interceptor.attach(func, {
      onEnter(args) {
        const proxy = new ObjC.Object(args[0]);
        const sel = ObjC.selectorAsString(args[1]);
        const clazz = proxy.$className;

        const signature = proxy.methodSignatureForSelector_(
          args[1],
        ) as ObjC.Object;

        let name = "";
        let peer = 0;

        {
          const { conn } = ObjC.getBoundData(args[0]);
          if (conn) {
            const connObj = new ObjC.Object(conn as NativePointer);
            if (typeof connObj.serviceName === "function") {
              name = connObj.serviceName() + "";
              peer = connObj.processIdentifier();
            }
          }
        }

        const json = {
          type: "nsxpc",
          sel,
          args: formatArgs(args, signature),
          description: formatDescription(args[0], clazz, sel, args),
        };

        const backtrace = bt(this.context);

        send({
          event: "sent",
          name,
          peer,
          direction: ">",
          message: json,
          backtrace,
        });
      },
    });
  }
}
