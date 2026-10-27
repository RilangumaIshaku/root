import { build } from 'esbuild';

const r = await build({
  entryPoints: ['src/main.js'],
  bundle: true,
  outfile: 'dist/bundle.js',
  format: 'iife',
  platform: 'browser',
  target: ['es2022'],
  // Shipped builds are minified with no source map: not protection, just a
  // smaller handle for casual reading. `--dev` keeps it readable for debugging.
  minify: !process.argv.includes('--dev'),
  sourcemap: false,
  legalComments: 'none',
  logLevel: 'info',
  banner: {
    js: '/* ROOT//NODE — bundled locally. No CDN, no analytics, no telemetry. */',
  },
});

if (r.errors.length) process.exit(1);
