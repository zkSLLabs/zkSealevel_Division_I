export function mapProgramError(err: unknown): { http: number; code: string; message: string; details: unknown } {
  const msg = err instanceof Error ? err.message : String(err);
  const to = (http: number, code: string) => ({ http, code, message: msg, details: null });
  if (/BadEd25519Order|6015/i.test(msg)) return to(400, "BadEd25519Order");
  if (/BadDomainSeparation|6016/i.test(msg)) return to(400, "BadDomainSeparation");
  if (/NonMonotonicSeq|6012/i.test(msg)) return to(400, "NonMonotonicSeq");
  if (/RangeOverlap|6013/i.test(msg)) return to(400, "RangeOverlap");
  if (/ClockSkew|6014/i.test(msg)) return to(400, "ClockSkew");
  if (/AggregatorMismatch|6006/i.test(msg)) return to(400, "AggregatorMismatch");
  if (/InvalidMint|6000/i.test(msg)) return to(400, "InvalidMint");
  if (/Paused|6010/i.test(msg)) return to(403, "Paused");
  return to(500, "AnchorSubmitFailed");
}


