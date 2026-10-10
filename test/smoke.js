import assert from 'node:assert/strict';
import { MaskEngine } from '../src/engine.js';
import { JsonlMaskTransform, CsvMaskTransform } from '../src/transformer.js';
import { Readable } from 'node:stream';

async function streamToString(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function runTests() {
  const secret = 'prod-incident-investigation-key-2025';
  const engine1 = new MaskEngine(secret);
  const engine2 = new MaskEngine(secret);
  const diffEngine = new MaskEngine('different-secret-key');

  // 1. Deterministic repeatability check
  const email = 'alice.dev@company.internal';
  const masked1 = engine1.maskEmail(email);
  const masked2 = engine2.maskEmail(email);
  assert.equal(masked1, masked2, 'Masking must be deterministic with identical key');
  assert.notEqual(masked1, email, 'Original email must be masked');
  assert.ok(masked1.endsWith('.internal'), 'Preserves target domain TLD');

  // 2. Secret isolation
  const maskedDiff = diffEngine.maskEmail(email);
  assert.notEqual(masked1, maskedDiff, 'Different keys must yield different masks');

  // 3. Format tests
  const ip = '192.168.1.50';
  const maskedIp = engine1.maskIpv4(ip);
  assert.ok(maskedIp.startsWith('10.'), 'IP is deterministically mapped to private range');

  const uuid = '550e8400-e29b-41d4-a716-446655440000';
  const maskedUuid = engine1.maskUuid(uuid);
  assert.equal(maskedUuid.length, 36, 'UUID length preserved');
  assert.match(maskedUuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[a-b0-9][0-9a-f]{3}-[0-9a-f]{12}$/i, 'UUID format preserved');

  // 4. JSONL streaming transform & referential integrity test
  const jsonlInput = [
    JSON.stringify({ userId: 'u-101', email: 'user1@acme.com', profile: { phone: '1-555-019-2834' } }),
    JSON.stringify({ userId: 'u-101', auditNote: 'Login by u-101 from user1@acme.com', ip: '172.16.0.1' }),
  ].join('\n');

  const rules = { userId: 'uuid', email: 'email', ip: 'ip', 'profile.phone': 'phone' };
  const jsonTransform = new JsonlMaskTransform(engine1, rules, false);
  const jsonInputStream = Readable.from([jsonlInput]);
  const jsonResult = await streamToString(jsonInputStream.pipe(jsonTransform));
  const [row1, row2] = jsonResult.trim().split('\n').map(l => JSON.parse(l));

  assert.equal(row1.userId, row2.userId, 'Referential integrity check: identical inputs must map identically across records');
  assert.notEqual(row1.email, 'user1@acme.com');
  assert.ok(row1.profile.phone.includes('-'), 'Phone format structure preserved');

  // 5. CSV streaming transform
  const csvInput = 'id,user_email,host_ip\n100,boss@corp.com,192.168.0.1\n101,dev@corp.com,192.168.0.2';
  const csvTransform = new CsvMaskTransform(engine1, { user_email: 'email', host_ip: 'ip' });
  const csvInputStream = Readable.from([csvInput]);
  const csvResult = await streamToString(csvInputStream.pipe(csvTransform));
  const lines = csvResult.trim().split('\n');

  assert.equal(lines[0], 'id,user_email,host_ip');
  assert.notEqual(lines[1].split(',')[1], 'boss@corp.com');
  assert.ok(lines[1].split(',')[2].startsWith('10.'));

  process.stdout.write('✔ All datum-mask smoke tests passed cleanly.\n');
}

runTests().catch(err => {
  process.stderr.write(`❌ Test failed: ${err.stack}\n`);
  process.exit(1);
});
