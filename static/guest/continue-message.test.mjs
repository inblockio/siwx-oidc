// Cross-language vector: the same fixed input as `continue_message_vector_matches_the_continue_page_builder`
// in src/guest_admission.rs. Run with: node --test static/guest/*.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildContinueMessage } from './continue-message.js';

export const VECTOR = {
  domain: 'id.example.org',
  alg: 'Ed25519',
  did: 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp',
  uri: 'https://id.example.org',
  nonce: 'aB3dE5gH7jK9mN1p',
  issuedAt: new Date('2026-10-11T12:34:56.000Z'),
  expiration: new Date('2026-10-11T12:39:56.789Z'),
  redirectUri: 'https://meet.example.org/auth/callback?x=1',
};

export const EXPECTED =
  'id.example.org wants you to sign in with your Ed25519 account:\n' +
  'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp\n' +
  '\n' +
  'Continue as a guest\n' +
  '\n' +
  'URI: https://id.example.org\n' +
  'Version: 1\n' +
  'Nonce: aB3dE5gH7jK9mN1p\n' +
  'Issued At: 2026-10-11T12:34:56.000Z\n' +
  'Expiration Time: 2026-10-11T12:39:56.789Z\n' +
  'Resources:\n' +
  '- https://meet.example.org/auth/callback?x=1';

test('the continue message matches the Rust vector byte for byte', () => {
  assert.equal(buildContinueMessage(VECTOR), EXPECTED);
});

test('a P-256 label and a port in the domain', () => {
  const m = buildContinueMessage({ ...VECTOR, alg: 'P-256', domain: 'localhost:31808', uri: 'http://localhost:31808' });
  assert.ok(m.startsWith('localhost:31808 wants you to sign in with your P-256 account:\n'));
  assert.ok(m.endsWith('\n- https://meet.example.org/auth/callback?x=1'));
});
