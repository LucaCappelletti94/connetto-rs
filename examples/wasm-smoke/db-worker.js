// DB worker bootstrap: import the wasm module named by the glue query
// parameter and boot the DB tier (OPFS replica, server connection, relay
// hub, hello channel intake). The parameter is read from import.meta.url,
// not self.location: a harness may load this script through a wrapper
// blob, and only the module URL keeps the query. Progress and failures go
// to connetto-debug for captured logs and to connetto-hello for the page
// readiness wait.
const debug = new BroadcastChannel("connetto-debug");
const hello = new BroadcastChannel("connetto-hello");

const params = new URL(import.meta.url).searchParams;
// The page spawns this worker with the identity of the boot it is waiting for, and a
// failure before the Rust side starts has to name it too.
const boot = params.get("boot");
if (boot) {
  self.connettoBoot = boot;
}

try {
  const glue = params.get("glue");
  debug.postMessage("db worker: importing " + glue);
  const mod = await import(glue);
  // The harness glue omits its default module path, so name the wasm
  // binary explicitly, derived from the glue URL.
  await mod.default({ module_or_path: glue.replace(/\.js$/, "_bg.wasm") });
  debug.postMessage("db worker: module ready, booting the db tier");
  await mod.db_worker_boot();
  debug.postMessage("db worker: serving");
} catch (err) {
  debug.postMessage("db worker FAILED: " + err);
  // A worker that cannot name its boot stays silent, because a page cannot attribute it.
  if (boot) {
    hello.postMessage("failed:" + boot + ":" + err);
  }
  throw err;
}
