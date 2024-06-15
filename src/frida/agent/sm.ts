function loadFramework() {
  const prefixes = ['', 'Private'];
  for (const prefix of prefixes) {
    const bundle = ObjC.classes.NSBundle.bundleWithPath_(`/System/Library/${prefix}Frameworks/ServiceManagement.framework`)
    if (bundle.load())
      return;
  }

  throw new Error('failed to load ServiceManagement.framework');
}

loadFramework();

const sm = Process.findModuleByName('ServiceManagement')!;
const kSMDomainUserLaunchd = sm.findExportByName('kSMDomainUserLaunchd')!;
const kSMDomainSystemLaunchd = sm.findExportByName('kSMDomainSystemLaunchd')!;
const SMCopyAllJobDictionaries = new NativeFunction(sm.findExportByName('SMCopyAllJobDictionaries')!, 'pointer', ['pointer']);

export function user() {
  return new ObjC.Object(SMCopyAllJobDictionaries(kSMDomainUserLaunchd));
}

export function system() {
  return new ObjC.Object(SMCopyAllJobDictionaries(kSMDomainSystemLaunchd));
}
