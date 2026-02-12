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

  return {
    dyldForEachInstalledSharedCache,
    dyldSharedCacheForEachImage,
    dyldImageGetInstallname,
    dyldImageLocalNlistContent4Symbolication,
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

function findSymbolInDyld(module: string, symbol: string) {
  let value = NULL;
  const symbolString = Memory.allocUtf8String(symbol);

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
                      if (strcmp(symbolName, symbolString) == 0) {
                        value = new NativePointer(n_value);
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

  return value;
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
  throw new Error("not implemented");
}
