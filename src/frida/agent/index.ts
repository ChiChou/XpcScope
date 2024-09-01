import { jobs } from './sm.js';
import { listeners, start as captureNSXPC } from './nsxpc.js';
import { start as captureXPC } from './libxpc.js';

if (!ObjC.available) throw new Error('Objective-C runtime is not available');

function stop() {
  Interceptor.detachAll();
}

rpc.exports = {
  nameAndPid: () => [Process.mainModule.name, Process.id] as [string, number],
  connections: () => ObjC.chooseSync(ObjC.classes.OS_xpc_connection).map(conn => conn.debugDescription().toString()),
  services(domain: string) {
    if (domain !== 'system' && domain !== 'user') 
      throw new Error(`invalid domain ${domain}`);

    return jobs(domain as 'system' | 'user');
  },
  listeners,
  start() {
    captureXPC();
    captureNSXPC();
  },
  stop,
}
