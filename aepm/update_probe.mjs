// Validate the installed helper's derived origin without emitting private addresses.
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

try {
  const context = JSON.parse(readFileSync(process.env.AEPM_CONTEXT_FILE, 'utf8'));
  let invitation = context.settings.updateUrl;
  if (!invitation) {
    const secrets = JSON.parse(readFileSync(process.env.AEPM_SECRETS_FILE, 'utf8'));
    invitation = secrets.values.updateInvitation.value;
  }
  const root = process.argv[2];
  const candidates = [join(root, 'components/store-update/server/store.ts'), join(root, 'implementation/server/store.ts')];
  const file = candidates.find(path => existsSync(path));
  if (!file) throw new Error('missing helper');
  const { updateUrlFor } = await import(pathToFileURL(file).href);
  const latest = updateUrlFor(invitation);
  const valid = typeof latest === 'string' && new URL(latest).origin === context.settings.updateReadOrigin;
  process.stdout.write(JSON.stringify({ valid }));
} catch {
  process.stdout.write('{"valid":false}');
  process.exitCode = 1;
}
