#!/usr/bin/env node

const required_packages = [
    'typescript',
    'tsup',
    '@changesets/cli',
    '@microsoft/api-extractor'
];

const missing_packages = [];
for (const package_name of required_packages) {
    try {
        const resolved_url = import.meta.resolve(package_name);
        if (!resolved_url) {
            missing_packages.push(package_name);
        }
    } catch {
        missing_packages.push(package_name);
    }
}

if (missing_packages.length > 0) {
    process.stderr.write(`Missing required SDK tooling: ${missing_packages.join(', ')}\n`);
    process.stderr.write('Install with: npm install --save-dev ' + missing_packages.join(' ') + '\n');
    process.exit(1);
}

const node_major_version = Number(process.versions.node.split('.')[0]);
if (!Number.isInteger(node_major_version) || node_major_version < 20) {
    process.stderr.write(`Node.js >=20 is required. Current version: ${process.versions.node}\n`);
    process.exit(1);
}

process.stdout.write('SDK preflight passed\n');
