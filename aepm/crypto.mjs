import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

let input = '';
for await (const chunk of process.stdin) input += chunk;
try {
  const request = JSON.parse(input);
  if (request.operation === 'public') {
    const key = createPublicKey(request.key);
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('key-type');
    process.stdout.write(Buffer.from(key.export({ format: 'jwk' }).x, 'base64url').toString('base64'));
  } else {
    const data = Buffer.from(request.data, 'base64');
    if (request.operation === 'sign') {
      const key = createPrivateKey(request.key);
      if (key.asymmetricKeyType !== 'ed25519') throw new Error('key-type');
      process.stdout.write(sign(null, data, key).toString('base64'));
    } else if (request.operation === 'verify') {
      const key = createPublicKey(request.key);
      if (key.asymmetricKeyType !== 'ed25519') throw new Error('key-type');
      process.stdout.write(verify(null, data, key, Buffer.from(request.signature, 'base64')) ? 'true' : 'false');
    } else throw new Error('operation');
  }
} catch {
  process.stderr.write('cryptographic operation failed\n');
  process.exitCode = 1;
}
