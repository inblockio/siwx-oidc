// Emits the license and notice texts of every npm package webpack actually
// bundles into the login page, so the MIT/BSD/Apache notice conditions travel
// with the JavaScript: the file is served next to the bundle
// (/build/third-party-licenses.txt) and the container image copies it to
// /usr/share/licenses/siwx-oidc/.
//
// Why not license-webpack-plugin: 4.0.2 (its latest release) reads a module's
// package from its identifier, and webpack 5 prefixes the identifier of every
// ES module with its type ("javascript/esm|/…/node_modules/viem/…"). The
// plugin does not strip that prefix, so it misses every package inside a
// concatenated ES module: on this bundle it listed eventemitter3 and nothing
// else. This plugin reads the owning package from webpack's own resolver data
// instead, which is what the bundle was built from.
//
// The build FAILS when a bundled package declares a license expression that is
// not in ACCEPTED_LICENSES, or ships no license file to copy. Both are meant to
// stop the build: the first needs a human to review the new license before it
// ships, the second means the notice obligation cannot be met automatically.

const fs = require('fs');
const path = require('path');
const webpack = require('webpack');

const PLUGIN = 'ThirdPartyLicensesPlugin';

// Exact SPDX expressions as written in package.json, reviewed for shipping in
// the login page. Add an expression only after reading the license.
const ACCEPTED_LICENSES = ['MIT'];

// Packages whose code reaches the output without being a bundled module:
// webpack emits its runtime (runtime.js) from RuntimeModules, and Tailwind
// generates the preflight rules in bundle.css. Neither carries resolver data.
const EMITTED_BY_TOOLING = ['webpack', 'tailwindcss'];

const LICENSE_FILE = /^(licen[cs]e|copying)/i;
const NOTICE_FILE = /^notice/i;

// The nearest package.json with a name and a version, walking up from `dir`
// but never out of node_modules. Some packages carry nested package.json files
// that only set "type" (viem/_esm/package.json), so the first one found is not
// always the package.
function owningPackage(dir) {
	while (dir.split(path.sep).includes('node_modules')) {
		const file = path.join(dir, 'package.json');
		if (fs.existsSync(file)) {
			const pkg = JSON.parse(fs.readFileSync(file, 'utf8'));
			if (pkg.name && pkg.version) return { dir, pkg };
		}
		dir = path.dirname(dir);
	}
	return null;
}

function packageDir(name, context) {
	return path.dirname(require.resolve(`${name}/package.json`, { paths: [context] }));
}

function licenseExpression(pkg) {
	if (typeof pkg.license === 'string') return pkg.license;
	if (pkg.license && typeof pkg.license.type === 'string') return pkg.license.type;
	return null;
}

function readMatching(dir, pattern) {
	return fs
		.readdirSync(dir)
		.filter((f) => pattern.test(f))
		.sort()
		.map((f) => fs.readFileSync(path.join(dir, f), 'utf8').replace(/\r\n/g, '\n').trimEnd());
}

class ThirdPartyLicensesPlugin {
	constructor({ filename }) {
		this.filename = filename;
	}

	apply(compiler) {
		// thisCompilation, not compilation: child compilers (mini-css-extract)
		// would otherwise emit a second, partial file.
		compiler.hooks.thisCompilation.tap(PLUGIN, (compilation) => {
			compilation.hooks.processAssets.tap(
				{ name: PLUGIN, stage: webpack.Compilation.PROCESS_ASSETS_STAGE_ADDITIONAL },
				() => this.emit(compiler, compilation),
			);
		});
	}

	emit(compiler, compilation) {
		const packages = new Map();
		const add = (owner) => packages.set(`${owner.pkg.name}@${owner.pkg.version}`, owner);

		const visit = (module) => {
			// A ConcatenatedModule holds the ES modules webpack merged into it.
			if (module.modules) module.modules.forEach(visit);
			const root = module.resourceResolveData && module.resourceResolveData.descriptionFileRoot;
			const owner = root && owningPackage(root);
			if (owner) add(owner);
		};
		for (const chunk of compilation.chunks) {
			for (const module of compilation.chunkGraph.getChunkModulesIterable(chunk)) visit(module);
		}
		for (const name of EMITTED_BY_TOOLING) {
			add(owningPackage(packageDir(name, compiler.context)));
		}

		const sections = [];
		for (const id of [...packages.keys()].sort()) {
			const { dir, pkg } = packages.get(id);
			const license = licenseExpression(pkg);
			if (!ACCEPTED_LICENSES.includes(license)) {
				compilation.errors.push(
					new webpack.WebpackError(
						`${PLUGIN}: ${id} is licensed "${license}", which is not in ACCEPTED_LICENSES ` +
							`(${path.relative(compiler.context, __filename)}). Review the license before adding it.`,
					),
				);
				continue;
			}
			const texts = readMatching(dir, LICENSE_FILE);
			if (texts.length === 0) {
				compilation.errors.push(
					new webpack.WebpackError(`${PLUGIN}: ${id} ships no LICENSE file to reproduce.`),
				);
				continue;
			}
			const notices = readMatching(dir, NOTICE_FILE);
			sections.push([`${id} (${license})`, '-'.repeat(80), ...texts, ...notices].join('\n\n'));
		}

		const header =
			'Third-party software in the siwx-oidc login page (static/build), with the\n' +
			'license and notice texts each package ships. Generated at build time from\n' +
			'the modules webpack bundled.';
		const rule = `\n\n${'='.repeat(80)}\n\n`;
		compilation.emitAsset(
			this.filename,
			new webpack.sources.RawSource(`${[header, ...sections].join(rule)}\n`),
		);
	}
}

module.exports = { ThirdPartyLicensesPlugin };
