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
          const beautifiedArgs = formatArgs(innerArgs, signature);

          const json = {
            type: "nsxpc",
            sel,
            args: beautifiedArgs,
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
        const formattedArgs = formatArgs(args, signature);

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

    Interceptor.attach(func, {
      onEnter(args) {
        const sel = ObjC.selectorAsString(args[1]);
        const proxy = new ObjC.Object(args[0]);
        const clazz = proxy.$className;

        const signature = proxy.methodSignatureForSelector_(
          args[1],
        ) as ObjC.Object;
        const beautifiedArgs = formatArgs(args, signature);

        const conn = new ObjC.Object(
          ObjC.getBoundData(args[0]).conn as NativePointer,
        );

        if (typeof conn.serviceName !== "function") return;

        const json = {
          type: "nsxpc",
          sel,
          args: beautifiedArgs,
          description: `${clazz} ${sel}`,
        };

        const backtrace = bt(this.context);

        send({
          event: "sent",
          name: conn.serviceName() + "",
          peer: conn.processIdentifier(),
          direction: ">",
          message: json,
          backtrace,
        });
      },
    });
  }
}
