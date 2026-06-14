// Dev helper: render the /account device list (via the mock wallet flow) and
// screenshot the card, to eyeball the View / Sign out button styling.
import { chromium } from '@playwright/test';
import { Wallet } from 'ethers';

const BASE = process.env.SIWEOIDC_HOST || 'http://localhost:8080';
const MOCK = process.env.SYNAPSE_MOCK || 'http://localhost:8090';
const wallet = new Wallet('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d');
const ADDRESS = wallet.address;
const MXID = `@${`did:pkh:eip155:1:${ADDRESS}`.replaceAll(':', '-').toLowerCase()}:matrix.test`;

await fetch(`${MOCK}/__reset`, { method: 'POST' });
for (const [id, name] of [['SIWX_phone', 'Element X (iPhone)'], ['SIWX_laptop', 'Element Web (Firefox)']]) {
  await fetch(`${MOCK}/__seed_device`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: MXID, device_id: id, display_name: name }),
  });
}

const browser = await chromium.launch();
const page = await browser.newPage({ deviceScaleFactor: 2 });
await page.exposeFunction('__ethSign', (m) => wallet.signMessage(m));
await page.addInitScript((addr) => {
  window.ethereum = {
    isMetaMask: true,
    request: async ({ method, params }) => {
      if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [addr];
      if (method === 'eth_chainId') return '0x1';
      if (method === 'personal_sign') return await window.__ethSign(params[0]);
      throw new Error('x' + method);
    },
    on() {}, removeListener() {},
  };
}, ADDRESS);

await page.goto(`${BASE}/account?action=org.matrix.devices_list`);
await page.click('#btn-wallet');
await page.locator('.device-row').first().waitFor();
await page.locator('.login-card').screenshot({ path: 'devicelist.png' });
console.log('saved devicelist.png');
await browser.close();
