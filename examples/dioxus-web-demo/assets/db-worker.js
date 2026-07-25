// DB worker bootstrap for the dioxus-web build.
//
// The dedicated DB worker shares the application's own wasm-bindgen module:
// db_worker_boot is a wasm_bindgen export of the same crate as the app. The
// glue URL is discovered on the main thread (a worker cannot see the main
// thread's resource timing) and handed to this script as the "glue" query
// parameter, read from import.meta.url rather than self.location because a
// bundler may load this script through a wrapper.
//
// dx appends an auto-init shim to the glue that fetches and initializes the
// wasm as a side effect of import and sets globalThis.__dx_mainWasm once it
// is ready. We wait for that instead of calling the init function again,
// which would instantiate a second, separate wasm module. The app's own
// main() returns early in a worker (no Window), so importing the glue is
// safe here.
//
// Progress and failures go to the connetto-debug broadcast channel, since a
// worker's console is not always visible to the page.
const debug = new BroadcastChannel("connetto-debug");

try {
  const glue = new URL(import.meta.url).searchParams.get("glue");
  debug.postMessage("db worker: importing " + glue);
  const mod = await import(glue);
  // Wait for dx's auto-init shim to finish initializing the shared wasm.
  while (globalThis.__dx_mainWasm === undefined) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  debug.postMessage("db worker: module ready, booting the db tier");
  await mod.db_worker_boot();
  debug.postMessage("db worker: serving");
} catch (err) {
  debug.postMessage("db worker FAILED: " + err);
  throw err;
}
