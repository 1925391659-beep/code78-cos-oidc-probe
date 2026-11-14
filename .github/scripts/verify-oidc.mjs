import { createPublicKey, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const issuer = 'https://token.actions.githubusercontent.com';
const ref = 'refs/heads/code78-oidc-probe';
const require = (condition, label) => { if (!condition) throw Error(label); };

export function expectedIdentity(workload, repository, repositoryId) {
  require(['api', 'worker'].includes(workload), 'WORKLOAD');
  require(/^[1-9]\d*$/.test(repositoryId), 'REPOSITORY_ID');
  require(/^[\w.-]+\/[\w.-]+$/.test(repository), 'REPOSITORY');
  const environment = 'code78-cos-' + workload + '-probe';
  const workflow = repository + '/.github/workflows/' + workload + '.yml@' + ref;
  const event = 'workflow_dispatch';
  return { repository, repositoryId, environment, workflow, event, ref, issuer,
    audience: 'urn:hnm:code78:cos:' + workload,
    subject: ['repository_id', repositoryId, 'environment', environment, 'ref', ref,
      'event_name', event, 'workflow_ref', workflow].join(':') };
}

export function verifyIdentity(token, jwks, expected, now) {
  require(typeof token === 'string' && token.length < 32768 && /^[\w-]+\.[\w-]+\.[\w-]+$/.test(token), 'TOKEN');
  const [header, payload, signature] = token.split('.');
  const h = JSON.parse(Buffer.from(header, 'base64url'));
  require(h.alg === 'RS256' && typeof h.kid === 'string', 'ALGORITHM');
  const matches = jwks.keys.filter(key => key.kid === h.kid && key.kty === 'RSA' && key.use === 'sig' && (!key.alg || key.alg === h.alg));
  require(matches.length === 1, 'KEY');
  require(verify('RSA-SHA256', Buffer.from(header + '.' + payload), createPublicKey({ key: matches[0], format: 'jwk' }), Buffer.from(signature, 'base64url')), 'SIGNATURE');
  const p = JSON.parse(Buffer.from(payload, 'base64url'));
  require(p.iss === expected.issuer && p.aud === expected.audience && p.sub === expected.subject, 'IDENTITY');
  require(p.repository === expected.repository && p.repository_id === expected.repositoryId && p.repository_visibility === 'public', 'REPOSITORY');
  require(p.environment === expected.environment && p.ref === expected.ref && p.event_name === expected.event && p.workflow_ref === expected.workflow, 'WORKFLOW');
  require([p.iat,p.nbf,p.exp].every(Number.isSafeInteger) && p.iat <= now + 30 && p.nbf <= now + 30 && now < p.exp && p.exp > p.iat && p.exp - p.iat <= 600, 'LIFETIME');
  return { issuer: p.iss, audience: p.aud, subject: p.sub, expiry: p.exp, keyId: h.kid };
}

async function main() {
  const identity = expectedIdentity(process.argv[2], process.env.PROBE_REPOSITORY, process.env.PROBE_REPOSITORY_ID);
  const request = new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);
  const issuerHost = new URL(issuer).hostname;
  const trustedHost = request.hostname === issuerHost || request.hostname.endsWith('.' + issuerHost);
  require(request.protocol === 'https:' && trustedHost && !request.username && !request.password && !request.port, 'TOKEN_ENDPOINT');
  request.searchParams.set('audience', identity.audience);
  const options = { redirect: 'error', signal: AbortSignal.timeout(10000) };
  const keys = await fetch(issuer + '/.well-known/jwks', options);
  require(keys.ok, 'JWKS');
  const response = await fetch(request, { ...options, headers: { authorization: 'Bearer ' + process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN } });
  require(response.ok, 'TOKEN_ENDPOINT');
  console.log(JSON.stringify(verifyIdentity((await response.json()).value, await keys.json(), identity, Math.floor(Date.now() / 1000))));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { console.error('OIDC verification failed'); process.exitCode = 1; });
}
