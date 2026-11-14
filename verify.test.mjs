import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { expectedIdentity, verifyIdentity } from './.github/scripts/verify-oidc.mjs';

const api = expectedIdentity('api', 'sample/probe', '42', '7');
const worker = expectedIdentity('worker', 'sample/probe', '42', '7');
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwks = { keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'fixture', use: 'sig' }] };
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
function fixture(id, overrides = {}) {
  const body = encode({ alg: 'RS256', kid: 'fixture' }) + '.' + encode({
    iss: id.issuer, aud: id.audience, sub: id.subject, repository: id.repository,
    repository_id: id.repositoryId, repository_owner_id: id.ownerId, repository_visibility: 'public',
    environment: id.environment, ref: id.ref, event_name: id.event, workflow_ref: id.workflow,
    iat: 990, nbf: 990, exp: 1100, ...overrides
  });
  return body + '.' + sign('RSA-SHA256', Buffer.from(body), privateKey).toString('base64url');
}
test('API and worker claims validate separately', () => {
  assert.notEqual(api.subject, worker.subject);
  for (const identity of [api, worker]) {
    assert.equal(verifyIdentity(fixture(identity), jwks, identity, 1000).subject, identity.subject);
  }
  assert.throws(() => verifyIdentity(fixture(api), jwks, worker, 1000), /IDENTITY/);
  assert.throws(() => verifyIdentity(fixture(worker), jwks, api, 1000), /IDENTITY/);
});
test('reject validly signed fork, PR, wrong workflow, branch, and expired claims', () => {
  for (const change of [
    { repository_id: '43' }, { repository_owner_id: '8' }, { repository: 'fork/probe' }, { event_name: 'pull_request' },
    { event_name: 'pull_request_target' }, { workflow_ref: worker.workflow },
    { ref: 'refs/heads/main' }, { ref: 'refs/tags/code78-oidc-probe' },
    { environment: worker.environment }, { sub: worker.subject }, { exp: 995 }
  ]) assert.throws(() => verifyIdentity(fixture(api, change), jwks, api, 1000));
  assert.throws(() => verifyIdentity(fixture(api), { keys: [] }, api, 1000), /KEY/);
});
