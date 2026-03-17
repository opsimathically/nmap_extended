import { defineConfig } from 'tsup';

export default defineConfig({
    entry: {
        index: 'src/index.ts',
        cli: 'src/cli.ts'
    },
    format: ['esm', 'cjs'],
    dts: true,
    target: 'node20',
    outDir: 'dist',
    clean: false,
    splitting: false,
    outExtension({ format }) {
        return format === 'esm'
            ? { js: '.mjs' }
            : { js: '.cjs' };
    }
});
