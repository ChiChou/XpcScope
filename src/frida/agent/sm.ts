function loadFramework() {
  const prefixes = ['', 'Private'];

  if (Process.findModuleByName('dyld_sim')) {
    throw new Error('this operation is not supported in iOS Simulator');
  }

  for (const prefix of prefixes) {
    const bundle = ObjC.classes.NSBundle.bundleWithPath_(`/System/Library/${prefix}Frameworks/ServiceManagement.framework`);
    if (bundle && bundle.load()) {
      return;
    }
  }

  throw new Error('failed to load ServiceManagement.framework');
}

type SMDomain = 'system' | 'user';

export function jobs(domain: SMDomain) {
  loadFramework();

  const sm = Process.findModuleByName('ServiceManagement')!;

  const kSMDomainUserLaunchd = sm.findExportByName('kSMDomainUserLaunchd')!;
  const kSMDomainSystemLaunchd = sm.findExportByName('kSMDomainSystemLaunchd')!;
  const SMCopyAllJobDictionaries = new NativeFunction(sm.findExportByName('SMCopyAllJobDictionaries')!, 'pointer', ['pointer']);

  const d = domain === 'system' ? kSMDomainSystemLaunchd : kSMDomainUserLaunchd;
  const dict = new ObjC.Object(SMCopyAllJobDictionaries(d));

  const NSPropertyListXMLFormat_v1_0 = 100;
  const data = ObjC.classes.NSPropertyListSerialization.dataWithPropertyList_format_options_error_(
    dict, NSPropertyListXMLFormat_v1_0, 0, NULL);
  return data.bytes().readUtf8String(data.length());
}
