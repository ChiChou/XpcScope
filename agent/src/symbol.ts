import ObjC from "frida-objc-bridge";
import { getGlobalExport } from "./polyfill.js";

function getDyldApi() {
  const libdyld = Module.load("/usr/lib/system/libdyld.dylib");
  // extern void dyld_for_each_installed_shared_cache(void (^block)(dyld_shared_cache_t cache));
  const dyld_for_each_installed_shared_cache = libdyld.findExportByName(
    "dyld_for_each_installed_shared_cache",
  );

  if (!dyld_for_each_installed_shared_cache) {
    throw new Error("dyld_for_each_installed_shared_cache not found");
  }

  const dyldForEachInstalledSharedCache = new NativeFunction(
    dyld_for_each_installed_shared_cache,
    "void",
    ["pointer"],
  );

  // extern void dyld_shared_cache_for_each_image(dyld_shared_cache_t cache, void (^block)(dyld_image_t image));
  const dyld_shared_cache_for_each_image = libdyld.findExportByName(
    "dyld_shared_cache_for_each_image",
  );

  if (!dyld_shared_cache_for_each_image) {
    throw new Error("dyld_shared_cache_for_each_image not found");
  }

  const dyldSharedCacheForEachImage = new NativeFunction(
    dyld_shared_cache_for_each_image,
    "void",
    ["pointer", "pointer"],
  );

  // extern const char* dyld_image_get_installname(dyld_image_t image);
  const dyld_image_get_installname = libdyld.findExportByName(
    "dyld_image_get_installname",
  );

  if (!dyld_image_get_installname) {
    throw new Error("dyld_image_get_installname not found");
  }

  const dyldImageGetInstallname = new NativeFunction(
    dyld_image_get_installname,
    "pointer",
    ["pointer"],
  );

  // extern bool dyld_image_local_nlist_content_4Symbolication(dyld_image_t image,
  //     void (^contentReader)(const void* nlistStart, uint64_t nlistCount,
  //                           const char* stringTable));
  const dyld_image_local_nlist_content_4Symbolication =
    libdyld.findExportByName("dyld_image_local_nlist_content_4Symbolication");

  if (!dyld_image_local_nlist_content_4Symbolication) {
    throw new Error("dyld_image_local_nlist_content_4Symbolication not found");
  }

  const dyldImageLocalNlistContent4Symbolication = new NativeFunction(
    dyld_image_local_nlist_content_4Symbolication,
    "bool",
    ["pointer", "pointer"],
  );

  // the following APIs are always present

  // uint32_t _dyld_image_count(void);
  const _dyld_image_count = new NativeFunction(
    getGlobalExport("_dyld_image_count"),
    "uint32",
    [],
  );

  // const _dyld_get_image_name = new NativeFunction(
  //   getGlobalExport("_dyld_get_image_name"),
  //   "pointer",
  //   ["uint32"],
  // );

  // uint32_t _dyld_image_count(void);
  const _dyld_get_image_header = new NativeFunction(
    getGlobalExport("_dyld_get_image_header"),
    "pointer",
    ["uint32"],
  );

  // int64_t _dyld_get_image_vmaddr_slide(uint32_t image_index);
  const _dyld_get_image_vmaddr_slide = new NativeFunction(
    getGlobalExport("_dyld_get_image_vmaddr_slide"),
    "int64",
    ["uint32"],
  );

  return {
    dyldForEachInstalledSharedCache,
    dyldSharedCacheForEachImage,
    dyldImageGetInstallname,
    dyldImageLocalNlistContent4Symbolication,

    _dyld_image_count,
    _dyld_get_image_header,
    _dyld_get_image_vmaddr_slide,
  };
}

// struct nlist_64 {
//     union {
//         uint32_t n_strx;  /* index into the string table */
//     } n_un;
//     uint8_t n_type;       /* type flag, see below */
//     uint8_t n_sect;       /* section number or NO_SECT */
//     uint16_t n_desc;      /* see <mach-o/stab.h> */
//     uint64_t n_value;     /* value of this symbol (or stab offset) */
// };

const strcmp = new NativeFunction(getGlobalExport("strcmp"), "int", [
  "pointer",
  "pointer",
]);

// int fnmatch(const char *pattern, const char *string, int flags);
const fnmatch = new NativeFunction(getGlobalExport("fnmatch"), "int", [
  "pointer",
  "pointer",
  "int",
]);

function getSlide(module: string) {
  const {
    _dyld_image_count,
    _dyld_get_image_header,
    _dyld_get_image_vmaddr_slide,
  } = getDyldApi();

  const moduleInfo = Process.getModuleByName(module);
  for (let i = 0; i < _dyld_image_count(); i++) {
    // const name = _dyld_get_image_name(i).readUtf8String()!;
    const header = _dyld_get_image_header(i);
    if (moduleInfo.base.equals(header)) {
      const slide = _dyld_get_image_vmaddr_slide(i);
      return slide;
    }
  }

  throw new Error(`module ${module} not found in current process`);
}

/**
 * Iterate over nlist symbols in the dyld shared cache for a given module.
 * @param visitor called for each symbol; return true to stop iteration.
 */
function forEachSymbolInDyld(
  module: string,
  visitor: (symbolName: NativePointer, value: UInt64) => boolean,
) {
  const {
    dyldForEachInstalledSharedCache,
    dyldSharedCacheForEachImage,
    dyldImageGetInstallname,
    dyldImageLocalNlistContent4Symbolication,
  } = getDyldApi();

  dyldForEachInstalledSharedCache(
    new ObjC.Block({
      retType: "void",
      argTypes: ["pointer"],
      implementation(cache) {
        let found = false;

        dyldSharedCacheForEachImage(
          cache,
          new ObjC.Block({
            retType: "void",
            argTypes: ["pointer"],
            implementation(image) {
              if (found) return;

              if (module !== null) {
                const name = dyldImageGetInstallname(image).readUtf8String()!;
                if (!name.endsWith("/" + module)) return;
                found = true;
              }

              dyldImageLocalNlistContent4Symbolication(
                image,
                new ObjC.Block({
                  retType: "bool",
                  argTypes: ["pointer", "uint64", "pointer"],
                  implementation(nlistStart, nlistCount, stringTable) {
                    let nlist = nlistStart;
                    for (
                      let i = uint64(0);
                      i.compare(nlistCount) < 0;
                      i = i.add(1), nlist = nlist.add(16)
                    ) {
                      const n_strx = nlist.readU32();
                      const n_value = nlist.add(8).readU64();
                      const symbolName = stringTable.add(n_strx);
                      if (visitor(symbolName, n_value)) {
                        break;
                      }
                    }
                  },
                }),
              );
            },
          }),
        );
      },
    }),
  );
}

function findSymbolInDyld(module: string, symbol: string) {
  let value = NULL;
  const symbolString = Memory.allocUtf8String("_" + symbol);

  forEachSymbolInDyld(module, (symbolName, n_value) => {
    if (strcmp(symbolName, symbolString) == 0) {
      value = new NativePointer(n_value);
      return true;
    }
    return false;
  });

  if (value.isNull())
    throw new Error(
      `symbol ${symbol} not found in dyld cache for module ${module}`,
    );

  const slide = getSlide(module);
  return value.add(slide);
}

function globSymbolsInDyld(module: string, pattern: string) {
  const results: NativePointer[] = [];
  const patternString = Memory.allocUtf8String("_" + pattern);

  forEachSymbolInDyld(module, (symbolName, n_value) => {
    if (fnmatch(patternString, symbolName, 0) === 0) {
      results.push(new NativePointer(n_value));
    }
    return false;
  });

  const slide = getSlide(module);
  return results.map((ptr) => ptr.add(slide));
}

export function find(module: string, symbol: string) {
  try {
    return findSymbolInDyld(module, symbol);
  } catch (e) {
    console.warn("Error finding symbol in dyld cache:", e);
    // fallback to slow
    return DebugSymbol.getFunctionByName(symbol);
  }
}

export function glob(module: string, pattern: string) {
  try {
    return globSymbolsInDyld(module, pattern);
  } catch (e) {
    console.warn("Error globbing symbols in dyld cache:", e);
    // fallback to slow
    return DebugSymbol.findFunctionsMatching(pattern);
  }
}
