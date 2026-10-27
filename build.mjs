import { build } from 'esbuild';

const r = await build({
  entryPoints: ['src/main.js'],
  bundle: true,
  outfile: 'dist/bundle.js',
  format: 'iife',
  platform: 'browser',
  target: ['es2022'],
  minify: process.argv.includes('--minify'),
  sourcemap: false,
  legalComments: 'none',
  logLevel: 'info',
  banner: {
    js: '/* ROOT//NODE — bundled locally. No CDN, no analytics, no telemetry. */',
  },
});

if (r.errors.length) process.exit(1);
