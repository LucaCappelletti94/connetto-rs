// Dedicated worker bootstrap for the webauthn-unlock harness.
//
// Mirrors the pattern in examples/wasm-smoke/db-worker.js: the glue module
// URL is passed as a query parameter so this script can serve any wasm-pack
// output without hardcoding a name.
//
// After the WASM module initialises:
//   1. `self.onmessage` routes tab replies to `receive_tab_answer`, which
//      resolves the one-shot promise `ask_tab` is waiting on.
//   2. `boot_worker` runs the test step appropriate for the current IDB state.

const debug = new BroadcastChannel("connetto-debug");

try {
    const glue = new URL(import.meta.url).searchParams.get("glue");
    debug.postMessage("webauthn-unlock worker: importing " + glue);
    const mod = await import(glue);
    await mod.default({ module_or_path: glue.replace(/\.js$/, "_bg.wasm") });
    debug.postMessage("webauthn-unlock worker: module ready");

    // Route tab replies into the Rust one-shot channel.
    self.onmessage = (e) => mod.receive_tab_answer(e.data);

    await mod.boot_worker();
    debug.postMessage("webauthn-unlock worker: boot_worker returned");
} catch (err) {
    debug.postMessage("webauthn-unlock worker FAILED: " + err);
    throw err;
}
