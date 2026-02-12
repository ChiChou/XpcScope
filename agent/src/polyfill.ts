interface Module16x17 {
  findGlobalExportByName(name: string): NativePointer;
  getGlobalExportByName(name: string): NativePointer;
  findExportByName(_: string | null, name: string): NativePointer;
  getExportByName(_: string | null, name: string): NativePointer;
}

export function getGlobalExport(name: string) {
  const m = Module as unknown as Module16x17;
  if (typeof m.getGlobalExportByName === "function")
    return m.getGlobalExportByName(name);
  return m.getExportByName(null, name);
}

export function findGlobalExport(name: string) {
  const m = Module as unknown as Module16x17;
  if (typeof m.findGlobalExportByName === "function")
    return m.findGlobalExportByName(name);
  return m.findExportByName(null, name);
}
