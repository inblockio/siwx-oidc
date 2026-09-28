/**
 * Test-only HTTPS pass-through proxy that serves a replacement /sw.js for one
 * Element origin, so a spec can run the UNPATCHED (stock) service worker against
 * a patched deployment and prove its assertions discriminate.
 *
 * Why a proxy and not context.route(): Chromium fetches a service worker's
 * script in the browser process. Neither context.route() nor a browser-level
 * CDP Fetch.enable sees the update check that follows a navigation (verified
 * 2026-09-28: the first install was replaced, the post-login soft update
 * silently re-installed the deployment's sw.js). A proxy sees every fetch.
 *
 * The browser is pointed here with --host-resolver-rules for the Element host
 * only (the origin, and therefore OIDC redirect URIs, cookies and IndexedDB,
 * stay exactly the deployment's), and --ignore-certificate-errors because the
 * proxy presents a throwaway self-signed certificate. Everything except /sw.js
 * is forwarded byte-for-byte to the real host's address.
 */
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import dns from 'node:dns/promises';
import { execFileSync } from 'node:child_process';

/** `workDir` receives a throwaway self-signed key pair (openssl). */
export async function startStockSwProxy({ elementUrl, swPath, workDir }) {
  const host = new URL(elementUrl).hostname;
  fs.mkdirSync(workDir, { recursive: true });
  const keyPath = path.join(workDir, 'key.pem');
  const certPath = path.join(workDir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-keyout', keyPath, '-out', certPath,
    '-subj', `/CN=${host}`, '-addext', `subjectAltName=DNS:${host}`,
  ], { stdio: 'ignore' });
  const { address } = await dns.lookup(host);
  const sw = fs.readFileSync(swPath);
  let served = 0;
  const server = https.createServer(
    { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) },
    (req, res) => {
      if (req.url.split('?')[0] === '/sw.js') {
        served++;
        res.writeHead(200, { 'Content-Type': 'application/javascript', 'Cache-Control': 'no-store' });
        res.end(sw);
        return;
      }
      const up = https.request(
        { host: address, servername: host, port: 443, method: req.method, path: req.url, headers: { ...req.headers, host } },
        (upRes) => {
          res.writeHead(upRes.statusCode, upRes.headers);
          upRes.pipe(res);
        },
      );
      up.on('error', () => {
        res.writeHead(502);
        res.end();
      });
      req.pipe(up);
    },
  );
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    served: () => served,
    launchArgs: [`--host-resolver-rules=MAP ${host}:443 127.0.0.1:${port}`, '--ignore-certificate-errors'],
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
