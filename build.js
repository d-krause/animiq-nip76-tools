#!/usr/bin/env node

const fs = require('fs')
const esbuild = require('esbuild')

let common = {
  entryPoints: ['src/index.ts'],
  bundle: true,
  sourcemap: 'external'
}

esbuild
  .build({
    ...common,
    outfile: 'lib/esm/animiq-nip76-tools.mjs',
    format: 'esm',
    packages: 'external'
  })
  .then(() => {
    const packageJson = JSON.stringify({type: 'module'})
    fs.writeFileSync(`${__dirname}/lib/esm/package.json`, packageJson, 'utf8')

    console.log('esm build success.')
  })

esbuild
  .build({
    ...common,
    outfile: 'lib/animiq-nip76-tools.cjs.js',
    format: 'cjs',
    packages: 'external'
  })
  .then(() => console.log('cjs build success.'))

// esbuild
//   .build({
//     ...common,
//     outfile: 'lib/animiq-nip76-tools.bundle.js',
//     format: 'iife',
//     globalName: 'animiqNip76Tools',
//     define: {
//       window: 'self',
//       global: 'self',
//       process: '{"env": {}}'
//     }
//   })
//   .then(() => console.log('standalone build success.'))