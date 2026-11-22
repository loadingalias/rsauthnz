// The dedicated Worker of `cargo xtask portable`. It instantiates the module with no imports, gives it a seed from
// `crypto.getRandomValues` and the time of `Date.now()`, and posts its report to the page. A trap posts its error.
(async () => {
  try {
    const bytes = await (await fetch('portable.wasm')).arrayBuffer();
    const { instance } = await WebAssembly.instantiate(bytes, {});
    const { memory, rsauthnz_portable_run: run, rsauthnz_portable_report: report } = instance.exports;
    const seed = crypto.getRandomValues(new BigUint64Array(4));
    const length = run(seed[0], seed[1], seed[2], seed[3], BigInt(Date.now()));
    postMessage(new TextDecoder().decode(new Uint8Array(memory.buffer, report(), length)));
  } catch (error) {
    postMessage('trap: ' + error + '\n');
  }
})();
