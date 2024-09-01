import plistlib
from ctypes import c_ulong, cdll, c_void_p, c_byte


def jobs(domain_system: bool = False):
    cf = cdll.LoadLibrary(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    cf.CFRelease.argtypes = [c_void_p]
    cf.CFRelease.restype = None
    cf.CFPropertyListCreateData.argtypes = [
        c_void_p, c_void_p, c_ulong, c_ulong, c_void_p]
    cf.CFPropertyListCreateData.restype = c_void_p
    cf.CFDataGetBytePtr.argtypes = [c_void_p]
    cf.CFDataGetBytePtr.restype = c_void_p
    cf.CFDataGetLength.argtypes = [c_void_p]
    cf.CFDataGetLength.restype = c_ulong

    # kCFPropertyListXMLFormat_v1_0 = 100
    kCFPropertyListBinaryFormat_v1_0 = 200

    sm = cdll.LoadLibrary(
        "/System/Library/Frameworks/ServiceManagement.framework/ServiceManagement")
    sm.SMCopyAllJobDictionaries.argtypes = [c_void_p]
    sm.SMCopyAllJobDictionaries.restype = c_void_p

    domain = sm.kSMDomainSystemLaunchd if domain_system else sm.kSMDomainUserLaunchd

    jobs = sm.SMCopyAllJobDictionaries(domain)
    cfdata = cf.CFPropertyListCreateData(
        None, jobs, kCFPropertyListBinaryFormat_v1_0, 0, None)
    size = cf.CFDataGetLength(cfdata)
    byteptr = cf.CFDataGetBytePtr(cfdata)

    serialized = bytes((c_byte * size).from_address(byteptr))
    cf.CFRelease(jobs)

    return plistlib.loads(serialized)
