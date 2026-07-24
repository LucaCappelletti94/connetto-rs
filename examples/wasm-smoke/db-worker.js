// DB worker bootstrap: import the wasm module named by the glue query
// parameter and boot the DB tier (OPFS replica, server connection, relay
// hub, hello channel intake). The parameter is read from import.meta.url,
// not self.location: a harness may load this script through a wrapper
// blob, and only the module URL keeps the query. Progress and failures go
// to the connetto-debug broadcast channel, since a worker's console is not
// always visible to the page.
const debug = new BroadcastChannel("connetto-debug");

try {
  const glue = new URL(import.meta.url).searchParams.get("glue");
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
  throw err;
}
