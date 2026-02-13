export function bt(context: CpuContext) {
  return Thread.backtrace(context, Backtracer.ACCURATE)
    .map((ptr) => DebugSymbol.fromAddress(ptr))
    .map(String);
}
