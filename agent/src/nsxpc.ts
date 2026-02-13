import ObjC from "frida-objc-bridge";
import { find, glob } from "./symbol.js";

// make sure the Foundation.framework is loaded
ObjC.classes.NSBundle.bundleWithPath_(
  "/System/Library/Frameworks/Foundation.framework",
).load();
const { NSXPCListener, NSXPCInterface, NSXPCConnection } = ObjC.classes;

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
  );

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
          const nargs = signature.numberOfArguments();
          const formattedArgs: string[] = [];
          for (let i = 2; i < nargs; i++) {
            // skip self and selector
            const arg = innerArgs[i];
            const t = signature.getArgumentTypeAtIndex_(i);
            const wrapped = t.toString().startsWith("@")
              ? new ObjC.Object(arg)
              : arg;
            formattedArgs.push(wrapped.toString());
          }

          const json = {
            type: "nsxpc",
            sel,
            args: formattedArgs,
            description: sel,
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
        const nargs = signature.numberOfArguments();
        const formattedArgs: string[] = [];
        for (let i = 2; i < nargs; i++) {
          // skip self and selector
          const arg = args[i];
          const t = signature.getArgumentTypeAtIndex_(i);
          const wrapped = t.toString().startsWith("@")
            ? new ObjC.Object(arg)
            : arg;
          formattedArgs.push(wrapped.toString());
        }

        const json = {
          type: "nsxpc",
          sel,
          args: formattedArgs,
          description: sel,
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
    const nargs = parseInt(name.charAt(name.length - 1), 10);

    Interceptor.attach(func, {
      onEnter(args) {
        const sel = ObjC.selectorAsString(args[1]);
        const formattedArgs: string[] = [];
        const clazz = new ObjC.Object(args[0]).$className;
        for (let i = 2; i < nargs; i++) {
          const arg = args[i];
          formattedArgs.push(arg.toString(16));
        }

        const conn = new ObjC.Object(
          ObjC.getBoundData(args[0]).conn as NativePointer,
        );

        if (typeof conn.serviceName !== "function") return;

        const json = {
          type: "nsxpc",
          sel,
          args: formattedArgs,
          description: `${clazz} ${sel}`,
        };

        send({
          event: "sent",
          name: conn.serviceName() + "",
          peer: conn.processIdentifier(),
          direction: ">",
          message: json,
        });
      },
    });
  }
}
