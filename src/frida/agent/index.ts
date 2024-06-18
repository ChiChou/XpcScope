import { user, system } from './sm.js';
import { listeners, start as captureNSXPC } from './nsxpc.js';
import { start as captureXPC } from './libxpc.js';

if (!ObjC.available) throw new Error('Objective-C runtime is not available');

function stop() {
  Interceptor.detachAll();
}

rpc.exports = {
  nameAndPid: () => [Process.mainModule ? Process.mainModule.name : Process.enumerateModules()[0].name, Process.id] as [string, number],
  connections: () => ObjC.chooseSync(ObjC.classes.OS_xpc_connection).map(conn => conn.debugDescription().toString()),
  services(domain: string) {
    return domain === 'system' ? system() : user();
  },
  listeners,
  start() {
    captureXPC();
    captureNSXPC();
  },
  stop,
}
