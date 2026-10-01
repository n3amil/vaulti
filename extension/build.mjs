// Assembles the extension for each browser: extension/dist/{firefox,chrome}
// plus a .zip of each. Expects the WebAssembly bindings in extension/pkg
// (scripts/docker.sh extension builds those first).
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const here = path.dirname(new URL(import.meta.url).pathname);
const root = path.join(here, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(here, 'src/manifest.json'), 'utf8'));
manifest.version = JSON.parse(fs.readFileSync(path.join(root, 'app/src-tauri/tauri.conf.json'), 'utf8')).version;

const variants = {
  // Firefox runs MV3 background scripts as event pages and needs an add-on id.
  firefox: {
    background: { scripts: ['background.js'], type: 'module' },
    browser_specific_settings: { gecko: { id: 'vaulti@n3amil.github.io', strict_min_version: '128.0' } },
  },
  chrome: { background: { service_worker: 'background.js', type: 'module' } },
};

for (const [name, extra] of Object.entries(variants)) {
  const out = path.join(here, 'dist', name);
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(path.join(out, 'icons'), { recursive: true });
  for (const f of fs.readdirSync(path.join(here, 'src'))) {
    if (f !== 'manifest.json') fs.copyFileSync(path.join(here, 'src', f), path.join(out, f));
  }
  fs.copyFileSync(path.join(root, 'app/ui/i18n.js'), path.join(out, 'i18n.js'));
  fs.cpSync(path.join(here, 'pkg'), path.join(out, 'pkg'), { recursive: true });
  fs.copyFileSync(path.join(root, 'app/src-tauri/icons/32x32.png'), path.join(out, 'icons/32.png'));
  fs.copyFileSync(path.join(root, 'app/src-tauri/icons/128x128.png'), path.join(out, 'icons/128.png'));
  fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify({ ...manifest, ...extra }, null, 2));
  const zip = path.join(here, 'dist', `vaulti-${name}-${manifest.version}.zip`);
  fs.rmSync(zip, { force: true });
  execFileSync('zip', ['-qr', zip, '.'], { cwd: out });
  console.log(`${name}: ${path.relative(root, out)} + ${path.relative(root, zip)}`);
}
