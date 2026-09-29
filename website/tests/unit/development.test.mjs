import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import navigation from '../../src/data/navigation.json' with { type: 'json' };
import { frontmatter, plainBody } from '../../scripts/content.mjs';
import { fileURLToPath } from 'node:url';

const root = new URL('../../', import.meta.url);
test('development navigation resolves marked task guides with canonical source links', async () => {
  const group = navigation.find(group => group.label === 'Current development');
  assert.ok(group);
  const slugs = group.items.map(item => item.slug);
  assert.deepEqual(slugs, ['development/overview', 'development/shared-endpoints', 'development/network-number', 'development/transports', 'development/bacnet-sc']);
  assert.equal(new Set(navigation.flatMap(group => group.items.map(item => item.slug))).size,
    navigation.reduce((sum, group) => sum + group.items.length, 0));
  for (const slug of slugs) {
    const path = fileURLToPath(new URL(`src/content/docs/${slug}.md`, root));
    const source = await readFile(path, 'utf8');
    const page = frontmatter(source);
    assert.ok(page.title && page.description, slug);
    const body = await plainBody(page.body, path, []);
    assert.match(body, /current development|unreleased source/i, slug);
    assert.ok(body.includes('https://github.com/jscott3201/rusty-bacnet/blob/dev/docs/'), slug);
    assert.ok(body.includes('## Next steps'), slug);
    assert.ok(!body.includes('cargo install bacnet-cli --version'), slug);
  }
});

test('release CLI source path is pinned while the lab remains release-scoped', async () => {
  const install = await readFile(new URL('src/content/docs/start/installation.mdx', root), 'utf8');
  assert.match(install, /git clone --branch v0\.11\.0/);
  assert.match(install, /cargo install --path crates\/bacnet-cli --locked/);
  assert.doesNotMatch(install, /cargo install bacnet-cli --version/);
  const lab = await readFile(new URL('src/content/docs/start/local-lab.mdx', root), 'utf8');
  assert.match(lab, /v0\.11\.0/);
  assert.match(lab, /loopback_lab\.py\?raw/);
});
