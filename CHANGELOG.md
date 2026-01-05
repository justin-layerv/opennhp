# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0 (2026-01-05)


### ⚠ BREAKING CHANGES

* Protocol incompatible with any existing GMSM deployments.

### Features

* **ac:** Add additional_tls_domains for apps.layerv.xyz cert ([1c303d1](https://github.com/layervai/nhp/commit/1c303d1447e8fd211a134c01cef8168edcb55f27))
* **ac:** Add use_production_acme variable for valid TLS certs ([092e460](https://github.com/layervai/nhp/commit/092e460cbe590274bcce2608b704571549c77bf9))
* Add /plugins/* routing to Console EC2 for NHP auth ([09015cf](https://github.com/layervai/nhp/commit/09015cf0a4f39e9731b89cf2ea6297b2440bb978))
* Add Console auto-init support with admin password configuration ([32cb244](https://github.com/layervai/nhp/commit/32cb244f4c7afe967aa0824c64e5187193018135))
* Add Console routing to bypass nhp-acd for login page ([8ded8bd](https://github.com/layervai/nhp/commit/8ded8bda0b94b56ad34c89bffb61412637523956))
* Add Demo Gateway and Console EC2 modules ([2b54fa8](https://github.com/layervai/nhp/commit/2b54fa8dc46d2a9539199540e2dc9b3e2c1d66cf))
* Add explicit CodeQL workflow for security scanning ([bf83215](https://github.com/layervai/nhp/commit/bf8321514bbce69c780d8a79ccd69aad497b709b))
* Add NHP Server plugin support with S3 deployment ([8dd4fc7](https://github.com/layervai/nhp/commit/8dd4fc7fbe0c3d4cd43a37325a1bf7197bc490de))
* add nhp-agent to Docker debugging environment ([a8fe76a](https://github.com/layervai/nhp/commit/a8fe76a70b9129913c67b7dac55a5359b2fbd97d))
* Add passcode plugin templates to Docker build ([e11c722](https://github.com/layervai/nhp/commit/e11c7221b26b6cbf2644a2a2a7f259b822d8fd1c))
* Add weekly PAT expiration check workflow ([e670b67](https://github.com/layervai/nhp/commit/e670b6716f33f48dda4f51ce9684cfbe77bf8580))
* Bake plugins into Docker image + Console EC2 + AC routing ([224c192](https://github.com/layervai/nhp/commit/224c192d78c8dceb07be141924177ee16de323fe))
* **console-ec2:** Add SSM parameter for Console public URL ([ab70d03](https://github.com/layervai/nhp/commit/ab70d0307871ea638ebacf10d4ea725d2c9a4670))
* **console-ec2:** Add two-domain architecture for NHP Console auth ([c013906](https://github.com/layervai/nhp/commit/c0139068e30242ab0ac50c00d0eded59b06d01d3))
* Docker Local Debugging Environment ([2bde3e8](https://github.com/layervai/nhp/commit/2bde3e88479927568349ac5071dff463e2715656))
* Docker Local Debugging Environment ([#1267](https://github.com/layervai/nhp/issues/1267)) ([2bde3e8](https://github.com/layervai/nhp/commit/2bde3e88479927568349ac5071dff463e2715656))
* **sandbox:** Enable hqdatamiddleware Traefik plugin ([da7250b](https://github.com/layervai/nhp/commit/da7250b19bd559c47194227679bc3e902805d57f))


### Bug Fixes

* **ac:** Use shared ac_id for knock routing ([2513a91](https://github.com/layervai/nhp/commit/2513a91579c06e851077dd22547fb03a9f63b058))
* Add AuthUrl to portal_sites ext_info for auth_code flow ([b4b85a2](https://github.com/layervai/nhp/commit/b4b85a2ee3cd8cf58bf9d713f917083ab5c50323))
* add CUSTOM_LD_FLAGS parameter for make  ref [#1262](https://github.com/layervai/nhp/issues/1262) ([#1263](https://github.com/layervai/nhp/issues/1263)) ([d798c88](https://github.com/layervai/nhp/commit/d798c88a12ab8b750bf7977b162c6cb6915200f2))
* Add ext_info fields for passcode plugin compatibility ([693d079](https://github.com/layervai/nhp/commit/693d0793dd0741d5ee8a3eb003d0de02b3ef6607))
* Add lambda:InvokeFunction to GitHub Actions IAM policy ([147662c](https://github.com/layervai/nhp/commit/147662c8bef7d8c2c807a39271fd9136417a7079))
* Add missing variables to sandbox environment ([5dd76de](https://github.com/layervai/nhp/commit/5dd76deab3a372c355f6e867bb3bac7e88a4aaf3))
* Build plugins inside Docker image for Go version compatibility ([d73039e](https://github.com/layervai/nhp/commit/d73039ee719ff8e0955fd5e40de22ee688135566))
* **build:** Remove latest-release job blocked by repository rulesets ([#24](https://github.com/layervai/nhp/issues/24)) ([bb78ddc](https://github.com/layervai/nhp/commit/bb78ddc427566ecf755bbaddc8a2cace19f555f9))
* **ci:** Add Console EC2 ASG refresh to deployment workflow ([94d6b5e](https://github.com/layervai/nhp/commit/94d6b5ebbb20d694ee4484c0ab8f0ce6677a4b6e))
* **ci:** add repo flag to gh release delete command ([#22](https://github.com/layervai/nhp/issues/22)) ([fdc534f](https://github.com/layervai/nhp/commit/fdc534ff700db5b13bc6dc8b626d0a231f0a5735))
* **ci:** Allow Release Please PRs to pass required checks ([#34](https://github.com/layervai/nhp/issues/34)) ([9682c30](https://github.com/layervai/nhp/commit/9682c30751f03073beef1d425194ec4f4e549412))
* **ci:** resolve latest-release immutable release error ([#21](https://github.com/layervai/nhp/issues/21)) ([520db3a](https://github.com/layervai/nhp/commit/520db3abde7745415f1724d1363b0c4c91d84bc5))
* **ci:** Skip at step level to ensure check names are created ([#35](https://github.com/layervai/nhp/issues/35)) ([a0c70df](https://github.com/layervai/nhp/commit/a0c70dfbe05316734fd5e93f4d287635e9fe6d8c))
* **ci:** use gh CLI instead of action for latest release ([#23](https://github.com/layervai/nhp/issues/23)) ([d9acb8b](https://github.com/layervai/nhp/commit/d9acb8b467d5c3dc7f1a3ebe2a4b1fbc69b9dd08))
* **console-ec2:** Resolve AC NLB DNS to IP for ipset rules ([e7dae27](https://github.com/layervai/nhp/commit/e7dae27edd8508e13ef84aa64c18667792cc7f83))
* **console-ec2:** Set maskhost=false to enable redirect_url in auth_code ([5394d42](https://github.com/layervai/nhp/commit/5394d4214a19c2bb060e13da236e846e3d5a3f5c))
* **crypto:** Validate ciphertext length in AESDecrypt ([#32](https://github.com/layervai/nhp/issues/32)) ([4bdebd0](https://github.com/layervai/nhp/commit/4bdebd08a4eb2b807d875f056df2a437467cd291))
* demo templates ([1f50bf1](https://github.com/layervai/nhp/commit/1f50bf181f33a26863c8ddd9b47a0ee5adfed62b))
* Enable CGO for server build to match plugin compatibility ([8653e57](https://github.com/layervai/nhp/commit/8653e57e94ae778845a44fb5494c029384bcfa04))
* fix escape mod bug ([#1257](https://github.com/layervai/nhp/issues/1257)) ([70166b4](https://github.com/layervai/nhp/commit/70166b46efba3725509a0e520acf89db3e156efc))
* Hardcode AWS role ARN for PR validation ([c21f117](https://github.com/layervai/nhp/commit/c21f11796785b384341a731565da227cef2054d8))
* image path issue in the doc ([4d9b4df](https://github.com/layervai/nhp/commit/4d9b4df6ab9beee81228d43fbdf1f35b6ac9a7dc))
* Install certbot DNS Route53 plugin for Console EC2 ([48d3930](https://github.com/layervai/nhp/commit/48d3930dfd34df1cbe615395e80b6ad0f4d35066))
* Make .gitignore core dump pattern more specific ([a6b3572](https://github.com/layervai/nhp/commit/a6b3572654fa7e01a17b4825f602f42b35b460b5))
* NHP infrastructure for Console integration ([a0c6d2a](https://github.com/layervai/nhp/commit/a0c6d2a6eb3e8c8d794b738ec5f54034325e904c))
* Optimize quick start doc ([64cdee8](https://github.com/layervai/nhp/commit/64cdee8183f3c5be5d38680e5e5958d005dd037e))
* Pass auth keys from sandbox environment to nhp module ([7730525](https://github.com/layervai/nhp/commit/77305255e0453b893957fb6b4754649ad9995ef6))
* Preserve AC peers when etcd config has no [[ACs]] section ([8b0ad3e](https://github.com/layervai/nhp/commit/8b0ad3e358e7367b40694a80492e914c1510025d))
* Run terraform plan+apply together to fix archive_file issue ([79718f2](https://github.com/layervai/nhp/commit/79718f215902fd33ed78450f2d9483a1720ea521))
* **sandbox:** Wire traefik_plugins through to AC module ([69c8433](https://github.com/layervai/nhp/commit/69c84339b448aa75356090f1916068f9a0d50f9e))
* **sandbox:** Wire use_production_acme and additional_tls_domains through env wrapper ([a3e4fea](https://github.com/layervai/nhp/commit/a3e4fea5e0aa6d67e15aac415529ae48ce3060d9))
* **security:** Bump golang.org/x/net to v0.38.0 in tests/integration ([ace5a93](https://github.com/layervai/nhp/commit/ace5a936c0a0516ed78a2008168ce39aad17b28c))
* Skip Claude review for dependabot PRs ([7e58c60](https://github.com/layervai/nhp/commit/7e58c6092af0c30ec993f9615e5b6c578b9b4738))
* Skip Slack notifications for pull requests ([#10](https://github.com/layervai/nhp/issues/10)) ([e95f1a8](https://github.com/layervai/nhp/commit/e95f1a884612652e812c0045ab4efd142bbe4798))
* Skip Terraform validate for Dependabot PRs ([b0c8aa2](https://github.com/layervai/nhp/commit/b0c8aa25ebfbd0803f1d4e3fede4fa24a4dc5e61))
* Terraform formatting ([f17549b](https://github.com/layervai/nhp/commit/f17549b3a4c3e81740a881150295733afb8603df))
* **terraform:** Allow GitHub Actions OIDC for pull request workflows ([#33](https://github.com/layervai/nhp/issues/33)) ([433c4e6](https://github.com/layervai/nhp/commit/433c4e67e8209ad710f6b0015e70bd103905e779))
* Use ANTHROPIC_API_KEY for Claude review workflow ([f6cbd95](https://github.com/layervai/nhp/commit/f6cbd957339713365c00ec9406a69ac86de32984))
* Use BuildKit secrets for private plugin repo clone ([30c37d6](https://github.com/layervai/nhp/commit/30c37d68af063762850704c460c1a496a1d82e81))
* Use list syntax for server_plugins in resource.toml template ([90f5c55](https://github.com/layervai/nhp/commit/90f5c5516ac851db06efb6a495bf1010e324d9bc))
* Use manual build mode for CodeQL Go analysis ([a77f873](https://github.com/layervai/nhp/commit/a77f873eb2ae4fc8883187aa25700b90f2a74481))
* Use PLUGIN_REPO_TOKEN for cross-repo plugin access ([17a4e4d](https://github.com/layervai/nhp/commit/17a4e4d70aada63f9c814806eb2876f2e351a801))


### Code Refactoring

* Remove Chinese crypto standards (GMSM/SM2/SM3/SM4) ([#18](https://github.com/layervai/nhp/issues/18)) ([520afc7](https://github.com/layervai/nhp/commit/520afc7d63c37700ab39aebd51fb070e0841c350))

## 1.0.0 (2026-01-05)


### ⚠ BREAKING CHANGES

* Protocol incompatible with any existing GMSM deployments.

### Features

* **ac:** Add additional_tls_domains for apps.layerv.xyz cert ([1c303d1](https://github.com/layervai/nhp/commit/1c303d1447e8fd211a134c01cef8168edcb55f27))
* **ac:** Add use_production_acme variable for valid TLS certs ([092e460](https://github.com/layervai/nhp/commit/092e460cbe590274bcce2608b704571549c77bf9))
* Add /plugins/* routing to Console EC2 for NHP auth ([09015cf](https://github.com/layervai/nhp/commit/09015cf0a4f39e9731b89cf2ea6297b2440bb978))
* Add Console auto-init support with admin password configuration ([32cb244](https://github.com/layervai/nhp/commit/32cb244f4c7afe967aa0824c64e5187193018135))
* Add Console routing to bypass nhp-acd for login page ([8ded8bd](https://github.com/layervai/nhp/commit/8ded8bda0b94b56ad34c89bffb61412637523956))
* Add Demo Gateway and Console EC2 modules ([2b54fa8](https://github.com/layervai/nhp/commit/2b54fa8dc46d2a9539199540e2dc9b3e2c1d66cf))
* Add explicit CodeQL workflow for security scanning ([bf83215](https://github.com/layervai/nhp/commit/bf8321514bbce69c780d8a79ccd69aad497b709b))
* Add NHP Server plugin support with S3 deployment ([8dd4fc7](https://github.com/layervai/nhp/commit/8dd4fc7fbe0c3d4cd43a37325a1bf7197bc490de))
* add nhp-agent to Docker debugging environment ([a8fe76a](https://github.com/layervai/nhp/commit/a8fe76a70b9129913c67b7dac55a5359b2fbd97d))
* Add passcode plugin templates to Docker build ([e11c722](https://github.com/layervai/nhp/commit/e11c7221b26b6cbf2644a2a2a7f259b822d8fd1c))
* Add weekly PAT expiration check workflow ([e670b67](https://github.com/layervai/nhp/commit/e670b6716f33f48dda4f51ce9684cfbe77bf8580))
* Bake plugins into Docker image + Console EC2 + AC routing ([224c192](https://github.com/layervai/nhp/commit/224c192d78c8dceb07be141924177ee16de323fe))
* **console-ec2:** Add SSM parameter for Console public URL ([ab70d03](https://github.com/layervai/nhp/commit/ab70d0307871ea638ebacf10d4ea725d2c9a4670))
* **console-ec2:** Add two-domain architecture for NHP Console auth ([c013906](https://github.com/layervai/nhp/commit/c0139068e30242ab0ac50c00d0eded59b06d01d3))
* Docker Local Debugging Environment ([2bde3e8](https://github.com/layervai/nhp/commit/2bde3e88479927568349ac5071dff463e2715656))
* Docker Local Debugging Environment ([#1267](https://github.com/layervai/nhp/issues/1267)) ([2bde3e8](https://github.com/layervai/nhp/commit/2bde3e88479927568349ac5071dff463e2715656))
* **sandbox:** Enable hqdatamiddleware Traefik plugin ([da7250b](https://github.com/layervai/nhp/commit/da7250b19bd559c47194227679bc3e902805d57f))


### Bug Fixes

* **ac:** Use shared ac_id for knock routing ([2513a91](https://github.com/layervai/nhp/commit/2513a91579c06e851077dd22547fb03a9f63b058))
* Add AuthUrl to portal_sites ext_info for auth_code flow ([b4b85a2](https://github.com/layervai/nhp/commit/b4b85a2ee3cd8cf58bf9d713f917083ab5c50323))
* add CUSTOM_LD_FLAGS parameter for make  ref [#1262](https://github.com/layervai/nhp/issues/1262) ([#1263](https://github.com/layervai/nhp/issues/1263)) ([d798c88](https://github.com/layervai/nhp/commit/d798c88a12ab8b750bf7977b162c6cb6915200f2))
* Add ext_info fields for passcode plugin compatibility ([693d079](https://github.com/layervai/nhp/commit/693d0793dd0741d5ee8a3eb003d0de02b3ef6607))
* Add lambda:InvokeFunction to GitHub Actions IAM policy ([147662c](https://github.com/layervai/nhp/commit/147662c8bef7d8c2c807a39271fd9136417a7079))
* Add missing variables to sandbox environment ([5dd76de](https://github.com/layervai/nhp/commit/5dd76deab3a372c355f6e867bb3bac7e88a4aaf3))
* Build plugins inside Docker image for Go version compatibility ([d73039e](https://github.com/layervai/nhp/commit/d73039ee719ff8e0955fd5e40de22ee688135566))
* **build:** Remove latest-release job blocked by repository rulesets ([#24](https://github.com/layervai/nhp/issues/24)) ([bb78ddc](https://github.com/layervai/nhp/commit/bb78ddc427566ecf755bbaddc8a2cace19f555f9))
* **ci:** Add Console EC2 ASG refresh to deployment workflow ([94d6b5e](https://github.com/layervai/nhp/commit/94d6b5ebbb20d694ee4484c0ab8f0ce6677a4b6e))
* **ci:** add repo flag to gh release delete command ([#22](https://github.com/layervai/nhp/issues/22)) ([fdc534f](https://github.com/layervai/nhp/commit/fdc534ff700db5b13bc6dc8b626d0a231f0a5735))
* **ci:** Allow Release Please PRs to pass required checks ([#34](https://github.com/layervai/nhp/issues/34)) ([9682c30](https://github.com/layervai/nhp/commit/9682c30751f03073beef1d425194ec4f4e549412))
* **ci:** resolve latest-release immutable release error ([#21](https://github.com/layervai/nhp/issues/21)) ([520db3a](https://github.com/layervai/nhp/commit/520db3abde7745415f1724d1363b0c4c91d84bc5))
* **ci:** use gh CLI instead of action for latest release ([#23](https://github.com/layervai/nhp/issues/23)) ([d9acb8b](https://github.com/layervai/nhp/commit/d9acb8b467d5c3dc7f1a3ebe2a4b1fbc69b9dd08))
* **console-ec2:** Resolve AC NLB DNS to IP for ipset rules ([e7dae27](https://github.com/layervai/nhp/commit/e7dae27edd8508e13ef84aa64c18667792cc7f83))
* **console-ec2:** Set maskhost=false to enable redirect_url in auth_code ([5394d42](https://github.com/layervai/nhp/commit/5394d4214a19c2bb060e13da236e846e3d5a3f5c))
* **crypto:** Validate ciphertext length in AESDecrypt ([#32](https://github.com/layervai/nhp/issues/32)) ([4bdebd0](https://github.com/layervai/nhp/commit/4bdebd08a4eb2b807d875f056df2a437467cd291))
* demo templates ([1f50bf1](https://github.com/layervai/nhp/commit/1f50bf181f33a26863c8ddd9b47a0ee5adfed62b))
* Enable CGO for server build to match plugin compatibility ([8653e57](https://github.com/layervai/nhp/commit/8653e57e94ae778845a44fb5494c029384bcfa04))
* fix escape mod bug ([#1257](https://github.com/layervai/nhp/issues/1257)) ([70166b4](https://github.com/layervai/nhp/commit/70166b46efba3725509a0e520acf89db3e156efc))
* Hardcode AWS role ARN for PR validation ([c21f117](https://github.com/layervai/nhp/commit/c21f11796785b384341a731565da227cef2054d8))
* image path issue in the doc ([4d9b4df](https://github.com/layervai/nhp/commit/4d9b4df6ab9beee81228d43fbdf1f35b6ac9a7dc))
* Install certbot DNS Route53 plugin for Console EC2 ([48d3930](https://github.com/layervai/nhp/commit/48d3930dfd34df1cbe615395e80b6ad0f4d35066))
* Make .gitignore core dump pattern more specific ([a6b3572](https://github.com/layervai/nhp/commit/a6b3572654fa7e01a17b4825f602f42b35b460b5))
* NHP infrastructure for Console integration ([a0c6d2a](https://github.com/layervai/nhp/commit/a0c6d2a6eb3e8c8d794b738ec5f54034325e904c))
* Optimize quick start doc ([64cdee8](https://github.com/layervai/nhp/commit/64cdee8183f3c5be5d38680e5e5958d005dd037e))
* Pass auth keys from sandbox environment to nhp module ([7730525](https://github.com/layervai/nhp/commit/77305255e0453b893957fb6b4754649ad9995ef6))
* Preserve AC peers when etcd config has no [[ACs]] section ([8b0ad3e](https://github.com/layervai/nhp/commit/8b0ad3e358e7367b40694a80492e914c1510025d))
* Run terraform plan+apply together to fix archive_file issue ([79718f2](https://github.com/layervai/nhp/commit/79718f215902fd33ed78450f2d9483a1720ea521))
* **sandbox:** Wire traefik_plugins through to AC module ([69c8433](https://github.com/layervai/nhp/commit/69c84339b448aa75356090f1916068f9a0d50f9e))
* **sandbox:** Wire use_production_acme and additional_tls_domains through env wrapper ([a3e4fea](https://github.com/layervai/nhp/commit/a3e4fea5e0aa6d67e15aac415529ae48ce3060d9))
* **security:** Bump golang.org/x/net to v0.38.0 in tests/integration ([ace5a93](https://github.com/layervai/nhp/commit/ace5a936c0a0516ed78a2008168ce39aad17b28c))
* Skip Claude review for dependabot PRs ([7e58c60](https://github.com/layervai/nhp/commit/7e58c6092af0c30ec993f9615e5b6c578b9b4738))
* Skip Slack notifications for pull requests ([#10](https://github.com/layervai/nhp/issues/10)) ([e95f1a8](https://github.com/layervai/nhp/commit/e95f1a884612652e812c0045ab4efd142bbe4798))
* Skip Terraform validate for Dependabot PRs ([b0c8aa2](https://github.com/layervai/nhp/commit/b0c8aa25ebfbd0803f1d4e3fede4fa24a4dc5e61))
* Terraform formatting ([f17549b](https://github.com/layervai/nhp/commit/f17549b3a4c3e81740a881150295733afb8603df))
* **terraform:** Allow GitHub Actions OIDC for pull request workflows ([#33](https://github.com/layervai/nhp/issues/33)) ([433c4e6](https://github.com/layervai/nhp/commit/433c4e67e8209ad710f6b0015e70bd103905e779))
* Use ANTHROPIC_API_KEY for Claude review workflow ([f6cbd95](https://github.com/layervai/nhp/commit/f6cbd957339713365c00ec9406a69ac86de32984))
* Use BuildKit secrets for private plugin repo clone ([30c37d6](https://github.com/layervai/nhp/commit/30c37d68af063762850704c460c1a496a1d82e81))
* Use list syntax for server_plugins in resource.toml template ([90f5c55](https://github.com/layervai/nhp/commit/90f5c5516ac851db06efb6a495bf1010e324d9bc))
* Use manual build mode for CodeQL Go analysis ([a77f873](https://github.com/layervai/nhp/commit/a77f873eb2ae4fc8883187aa25700b90f2a74481))
* Use PLUGIN_REPO_TOKEN for cross-repo plugin access ([17a4e4d](https://github.com/layervai/nhp/commit/17a4e4d70aada63f9c814806eb2876f2e351a801))


### Code Refactoring

* Remove Chinese crypto standards (GMSM/SM2/SM3/SM4) ([#18](https://github.com/layervai/nhp/issues/18)) ([520afc7](https://github.com/layervai/nhp/commit/520afc7d63c37700ab39aebd51fb070e0841c350))

## [Unreleased]

## [0.6.0] - 2025-06-11

### Added
- eBPF/XDP packet filtering support for high-performance knocking
- Docker local debugging environment
- `PASS_KNOCKIP_WITH_RANGE` mode for AC to include IP address ranges

### Changed
- Refactored peer hostname resolve logic
- Aligned UDP open resource behavior with HTTP version
- Server now continues when AC connections are lost in resource groups

### Fixed
- CGO compilation issues
- Escape mod bug
- Possible nil pointer dereference
- Size comparison error

## [0.5.0] - 2025-04-13

### Added
- Plugin system for NHP-Server with separate modules
- Improved build system for server plugins

### Changed
- Separated modules to accommodate building of nhp-serverd and its plugins

## [0.4.1] - 2025-04-06

### Added
- DHP (Data Hiding Protocol) function code
- SM2 P256 ECDH curve support
- Default cipher scheme configuration for DE

### Changed
- Using GMSM as default cipher scheme
- Updated Makefile for building DE on Linux

### Fixed
- Removed redundant logging
- Fixed SM2 P256 ECDH curve usage

## [0.4.0] - 2024-09-04

### Added
- Initial public release
- Jekyll-based documentation site
- GitHub Pages deployment

### Changed
- Updated code structure and symbols to be more self-explanatory

## [0.3.6] - 2024-09-03

### Added
- Pre-release version with core NHP protocol implementation
- Agent, Server, and AC components
- Noise Protocol Framework integration
- Curve25519 and SM2 cipher scheme support

[Unreleased]: https://github.com/OpenNHP/opennhp/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/OpenNHP/opennhp/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/OpenNHP/opennhp/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/OpenNHP/opennhp/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/OpenNHP/opennhp/compare/v0.3.6...v0.4.0
[0.3.6]: https://github.com/OpenNHP/opennhp/releases/tag/v0.3.6
