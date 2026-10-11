// Cross-language vector: the same fixed input as `redeem_message_vector` in
// src/guest_admission.rs. Run with: node --test static/guest/guest-key.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRedeemMessage, didFromRaw, base58btc, base64url } from './guest-key.js';

export const VECTOR = {
  domain: 'id.example.org',
  alg: 'Ed25519',
  did: 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp',
  uri: 'https://id.example.org',
  nonce: '1700000300.AAAA_nonce-tag',
  issuedAt: new Date('2026-10-11T12:34:56.000Z'), // zero milliseconds on purpose
  expiration: new Date('2026-10-11T12:39:56.789Z'),
  inviteId: 'inv_0123456789abcdef',
};

export const EXPECTED =
  'id.example.org wants you to sign in with your Ed25519 account:\n' +
  'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp\n' +
  '\n' +
  'Join as a guest\n' +
  '\n' +
  'URI: https://id.example.org\n' +
  'Version: 1\n' +
  'Nonce: 1700000300.AAAA_nonce-tag\n' +
  'Issued At: 2026-10-11T12:34:56.000Z\n' +
  'Expiration Time: 2026-10-11T12:39:56.789Z\n' +
  'Resources:\n' +
  '- urn:io.inblock:guest:invite:inv_0123456789abcdef';

test('the redeem message matches the Rust vector byte for byte', () => {
  assert.equal(buildRedeemMessage(VECTOR), EXPECTED);
});

test('a P-256 label and a port in the domain', () => {
  const m = buildRedeemMessage({ ...VECTOR, alg: 'P-256', domain: 'localhost:31808', uri: 'http://localhost:31808' });
  assert.ok(m.startsWith('localhost:31808 wants you to sign in with your P-256 account:\n'));
  assert.ok(m.includes('\nURI: http://localhost:31808\n'));
});

test('did:key of the all-zero Ed25519 key is the well-known value', () => {
  // multicodec ed01 + 32 zero bytes
  assert.equal(didFromRaw('Ed25519', new Uint8Array(32)), 'did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP');
});

test('P-256 did:key compresses the point and uses the 0x1200 prefix', () => {
  const raw = new Uint8Array(65);
  raw[0] = 4; raw[1] = 7; raw[64] = 3; // odd y
  const did = didFromRaw('P-256', raw);
  assert.ok(did.startsWith('did:key:zDn'));
});

test('base64url has no padding and no +/', () => {
  assert.equal(base64url(new Uint8Array([251, 255, 254])), '-__-');
  assert.equal(base58btc(new Uint8Array([0, 0, 1])), '112');
});
