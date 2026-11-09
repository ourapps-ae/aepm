// Actual locked-browser trials; only local blank content and private profiles.
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';

async function rejectingEndpoint() {
  const sockets = new Set();
  const server = createServer((_request, response) => { response.writeHead(403); response.end(); });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('upgrade', (_request, socket) => {
    socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n', () => socket.destroy());
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return {
    endpoint: `ws://127.0.0.1:${server.address().port}/devtools/browser/controlled-refusal`,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
    },
  };
}

const [mode, launcherFile, trial] = process.argv.slice(2);
const profileRoot = path.join(trial, 'profiles/browser');
await fs.mkdir(profileRoot, { recursive: true, mode: 0o700 });
const ready = async browserIds => {
  await fs.writeFile(path.join(trial, 'ready.pending'), JSON.stringify({ helper: process.pid, browserIds }));
  await fs.rename(path.join(trial, 'ready.pending'), path.join(trial, 'ready.json'));
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    try { await fs.access(path.join(trial, 'release')); return; } catch { /* Parent records identities before release. */ }
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('acceptance-handshake-timeout');
};

if (mode === 'probe-connection') {
  const { createRequire } = await import('node:module');
  const { chromium } = createRequire(pathToFileURL(launcherFile))('playwright');
  const refusing = await rejectingEndpoint();
  let rejected = false;
  try { await chromium.connectOverCDP(refusing.endpoint, { timeout: 1000 }); }
  catch { rejected = true; }
  finally { await refusing.close(); }
  if (!rejected) throw new Error('controlled-refusal-was-accepted');
  console.log(JSON.stringify({ connectionRejected: true }));
} else if (mode === 'startup-failure' || mode === 'connection-failure') {
  const core = await import(pathToFileURL(path.join(path.dirname(launcherFile), 'browser-process-core.mjs')).href);
  await core.configurePrivateBrowserCache();
  const { createRequire } = await import('node:module');
  const require = createRequire(pathToFileURL(launcherFile));
  const { chromium } = require('playwright');
  const refusing = mode === 'connection-failure' ? await rejectingEndpoint() : null;
  let child;
  let observed;
  let releaseObservation;
  observed = new Promise(resolve => { releaseObservation = resolve; });
  const launch = core.createOwnedBrowserLauncher({
    spawn: (...args) => {
      child = spawn(...args);
      child.once('spawn', () => { ready([child.pid]).then(releaseObservation); });
      return child;
    },
    chromium: {
      executablePath: () => chromium.executablePath(),
      connectOverCDP: async endpoint => {
        await observed;
        if (mode === 'startup-failure') {
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
          throw new Error('controlled-startup-failure');
        }
        return await chromium.connectOverCDP(refusing.endpoint, { timeout: 1000 });
      },
    },
  });
  try {
    await launch({ profileRoot, timeoutMilliseconds: 30000 });
    throw new Error('unexpected-startup-success');
  } catch (error) {
    if (error.message !== 'process-failed' || !child || child.exitCode === null && child.signalCode === null) throw error;
    console.log(JSON.stringify({ mode, expectedFailure: true, childExited: true }));
  } finally {
    if (refusing) await refusing.close();
  }
} else {
  const { launchOwnedBrowser } = await import(pathToFileURL(launcherFile).href);
  const owned = await launchOwnedBrowser({ profileRoot, timeoutMilliseconds: 30000 });
  try {
    const context = await owned.browser.newContext();
    const page = await context.newPage();
    await page.setContent('<!doctype html><title>Owned fixture</title><p>Local fixture</p>');
    if (await page.title() !== 'Owned fixture') throw new Error('page-assertion');
    const session = await owned.browser.newBrowserCDPSession();
    const { processInfo } = await session.send('SystemInfo.getProcessInfo');
    await ready(processInfo.map(item => item.id));
    if (mode === 'forced-exit') process.exit(23);
    if (mode === 'timeout') await page.evaluate(() => new Promise(() => {}));
    if (mode !== 'normal') throw new Error('unknown-mode');
  } finally {
    await owned.close();
  }
  console.log(JSON.stringify({ mode, closed: true }));
}
