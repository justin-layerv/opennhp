# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0](https://github.com/layervai/nhp/compare/v1.0.0...v2.0.0) (2026-02-03)


### ⚠ BREAKING CHANGES

* **server:** License records with empty hash are now rejected.

### Features

* **ac:** implement Phase 3 AC server assignment flow ([#122](https://github.com/layervai/nhp/issues/122)) ([619ff91](https://github.com/layervai/nhp/commit/619ff911ec37358c994fc90774d94c4a792d3f79))
* add /cr slash command for code review response ([#203](https://github.com/layervai/nhp/issues/203)) ([91ca26e](https://github.com/layervai/nhp/commit/91ca26e13459ab00e4aad6a2ce9335d76e5f2a47))
* add /externalize-defaults slash command ([#205](https://github.com/layervai/nhp/issues/205)) ([d8eb30c](https://github.com/layervai/nhp/commit/d8eb30ceb364daee4251dd8c34bf782776300218))
* **console-ec2:** add true NHP network-level protection option ([#49](https://github.com/layervai/nhp/issues/49)) ([81167cc](https://github.com/layervai/nhp/commit/81167cc8653a96815d135a8971149db398aa796c))
* **console-ec2:** enable true NHP network-level protection ([#62](https://github.com/layervai/nhp/issues/62)) ([0229906](https://github.com/layervai/nhp/commit/02299061df5993243679c11a633e1a7daae85368))
* **console-ec2:** use Docker-based migrations ([#37](https://github.com/layervai/nhp/issues/37)) ([1b68114](https://github.com/layervai/nhp/commit/1b68114dc0b6a47145003cbe617afc92650bd386))
* **dynamodb:** add server-ac-index table for efficient server lookups ([#130](https://github.com/layervai/nhp/issues/130)) ([f1c28bf](https://github.com/layervai/nhp/commit/f1c28bf07a768785bb425caee52dad763f92c511))
* **nhp:** Phase 2 protocol changes for pluggable storage backend ([#118](https://github.com/layervai/nhp/issues/118)) ([801e6ee](https://github.com/layervai/nhp/commit/801e6eee49bd34ec1a5dde43a658a2f3ec7beeba))
* **server:** add QURL plugin for token resolution ([#201](https://github.com/layervai/nhp/issues/201)) ([1c52dbb](https://github.com/layervai/nhp/commit/1c52dbb46c1d3c9826b975f1d89ab1ab7bd7b304))
* **server:** implement etcd storage backend for on-prem deployments ([#126](https://github.com/layervai/nhp/issues/126)) ([b456966](https://github.com/layervai/nhp/commit/b4569666bf2a3d42c212345864b75085c4be6d5e))
* **terraform:** add ACM certificate for QURL API domain ([#266](https://github.com/layervai/nhp/issues/266)) ([1d12c10](https://github.com/layervai/nhp/commit/1d12c106148898d1946dc9d1fa98b75b2bb386b0))
* **terraform:** add ASG lifecycle hook for immediate DynamoDB cleanup ([#200](https://github.com/layervai/nhp/issues/200)) ([3b3bedd](https://github.com/layervai/nhp/commit/3b3bedddecf9158746114a325ed332b09b5894ef))
* **terraform:** add Auth0 secret rotation and fix qurl_auth0_domain passthrough ([#258](https://github.com/layervai/nhp/issues/258)) ([174ead5](https://github.com/layervai/nhp/commit/174ead5a8103086b22d415d8f04cc658f544a493))
* **terraform:** add Auth0 Terraform module for identity management ([#254](https://github.com/layervai/nhp/issues/254)) ([c7a2816](https://github.com/layervai/nhp/commit/c7a281647a8a8b995d449c2f880231a6f7b02833))
* **terraform:** add centralized TLS certificate management for ACs ([#277](https://github.com/layervai/nhp/issues/277)) ([dd8a4bc](https://github.com/layervai/nhp/commit/dd8a4bcb8695788b140ef829f7f99e664c7d3963))
* **terraform:** add missing QURL service env vars for fail-fast config ([#243](https://github.com/layervai/nhp/issues/243)) ([6112a37](https://github.com/layervai/nhp/commit/6112a37ddd193d94677c378eb7f2df7b88a8de31))
* **terraform:** add multi-zone support to ACME cert manager ([#309](https://github.com/layervai/nhp/issues/309)) ([cf3b441](https://github.com/layervai/nhp/commit/cf3b441cc150fc89e474c38546677af3f5af2c8b))
* **terraform:** add NACL rule for NHP-protected private subnet ingress ([#69](https://github.com/layervai/nhp/issues/69)) ([9e6883c](https://github.com/layervai/nhp/commit/9e6883c34a60d22da540dd8061bab696785cf4ca))
* **terraform:** add QURL env vars, licensing integration, and Grafana Cloud telemetry ([#211](https://github.com/layervai/nhp/issues/211)) ([f5c89c7](https://github.com/layervai/nhp/commit/f5c89c7edabb8904b35499ec8af2d92595644213))
* **terraform:** add QURL link redirect page with cross-account Route53 for qurl.link ([#271](https://github.com/layervai/nhp/issues/271)) ([4c8ec45](https://github.com/layervai/nhp/commit/4c8ec45bb3bb2a7f230e0271548351d3918be0e6))
* **terraform:** add QURL service ECS Fargate module ([#208](https://github.com/layervai/nhp/issues/208)) ([b168294](https://github.com/layervai/nhp/commit/b168294bf18b1dd7ff13c609bf5b4cc932e2f857))
* **terraform:** add SSM parameters for QURL ECS config ([#255](https://github.com/layervai/nhp/issues/255)) ([cc8a3fe](https://github.com/layervai/nhp/commit/cc8a3fef609cb6636416e346ce5988a73611ecc2))
* **terraform:** enable centralized TLS certificate management in sandbox ([#278](https://github.com/layervai/nhp/issues/278)) ([1b919f8](https://github.com/layervai/nhp/commit/1b919f8f92e36ae99c1c1edbd463eb71636fe0e8))
* **terraform:** enable Console AC license validation for sandbox ([#147](https://github.com/layervai/nhp/issues/147)) ([498da69](https://github.com/layervai/nhp/commit/498da695f54fe1cc4d2e173d4931ada776021f75))
* **terraform:** enable full GuardDuty protection features ([#159](https://github.com/layervai/nhp/issues/159)) ([ea854b1](https://github.com/layervai/nhp/commit/ea854b1dcf063b605bef78407a1ae67638d81547))
* **terraform:** enable QURL router plugin in sandbox ([#311](https://github.com/layervai/nhp/issues/311)) ([fd62250](https://github.com/layervai/nhp/commit/fd622505ef3093debb80c484fd141d58ce6e3368))
* **terraform:** Phase 1 pluggable storage backend infrastructure (DynamoDB for cloud) ([#117](https://github.com/layervai/nhp/issues/117)) ([28b45a2](https://github.com/layervai/nhp/commit/28b45a2a4d7b2012ce8351f67d2a57035154c054))
* **terraform:** read Console image tag from SSM at boot time ([#170](https://github.com/layervai/nhp/issues/170)) ([ae28a28](https://github.com/layervai/nhp/commit/ae28a28db8f60f3a4b8692f6b07d0ed203fb6ec9))


### Bug Fixes

* **ac:** add HTTP matcher to NLB health check ([#310](https://github.com/layervai/nhp/issues/310)) ([24ce602](https://github.com/layervai/nhp/commit/24ce602b88242ddb596b15eeed2d8a2519fe9d59))
* **ac:** add periodic registration refresh to handle server restarts ([#327](https://github.com/layervai/nhp/issues/327)) ([536f739](https://github.com/layervai/nhp/commit/536f739619d06e0cdf8452dd52301f8a2f14caee))
* **ac:** add ProxyProtocol to Traefik health check entrypoint ([#319](https://github.com/layervai/nhp/issues/319)) ([f9bb5d7](https://github.com/layervai/nhp/commit/f9bb5d794ac4cd317ed5e7c0d1409c0f51a713b9))
* **ac:** add registration server to assignedServers for keepalive ([#294](https://github.com/layervai/nhp/issues/294)) ([fb57f5f](https://github.com/layervai/nhp/commit/fb57f5f8deec8e9687cf6a11fbbaea96642a8d42))
* **ac:** block private IP direct connections from external ACs ([#302](https://github.com/layervai/nhp/issues/302)) ([7c5ec98](https://github.com/layervai/nhp/commit/7c5ec984c13ae5122c4b58190ba8030b11a2b077))
* **ac:** enforce NHP port hiding for ports 443 and 80 ([#308](https://github.com/layervai/nhp/issues/308)) ([4e31504](https://github.com/layervai/nhp/commit/4e3150472c54b7745ada8d31f1a4034a418cb675))
* **ac:** establish direct connection to server instead of NLB ([#297](https://github.com/layervai/nhp/issues/297)) ([c947f5d](https://github.com/layervai/nhp/commit/c947f5d6b5be44c75d6e6ebdf96f6b483038c1cc))
* **ac:** handle 0.0.0.0 sentinel IP for QURL resources ([#295](https://github.com/layervai/nhp/issues/295)) ([fe06b11](https://github.com/layervai/nhp/commit/fe06b11967f231d18c06df77e93570cf98eff45e))
* **ac:** invalidate DNS cache on connection failures ([#93](https://github.com/layervai/nhp/issues/93)) ([4e1f391](https://github.com/layervai/nhp/commit/4e1f391033a5658d4716ae770b3a418a47b55489))
* **ac:** keep server peer after NHP_AAK for knock operations ([#192](https://github.com/layervai/nhp/issues/192)) ([918b83a](https://github.com/layervai/nhp/commit/918b83a50d9239258baf0d7d7ac4feefba15768b))
* **ac:** prevent fail-open in cloud mode when no servers configured ([#321](https://github.com/layervai/nhp/issues/321)) ([e9e433d](https://github.com/layervai/nhp/commit/e9e433dd6518ef80713e24a6ec9f84abb116f32d))
* **ac:** prevent test timeout in recv routine cleanup ([#301](https://github.com/layervai/nhp/issues/301)) ([5ed4f8e](https://github.com/layervai/nhp/commit/5ed4f8e196b21cefb95de63993950929300e097e))
* **ac:** re-resolve server DNS on each discovery iteration ([#75](https://github.com/layervai/nhp/issues/75)) ([68c46f5](https://github.com/layervai/nhp/commit/68c46f53362e05a450de7aacbd4b95226ae45f0b))
* **ac:** reset iptables after successful cloud-mode registration ([#313](https://github.com/layervai/nhp/issues/313)) ([d909226](https://github.com/layervai/nhp/commit/d9092262b951e0076df1b836d831570ca8c2db41))
* **ac:** update LastSeen using actual packet source address ([#299](https://github.com/layervai/nhp/issues/299)) ([8e63ef4](https://github.com/layervai/nhp/commit/8e63ef457b9d0bda2889eec32090e274bd1e110c))
* **ac:** update LastSeen using server public key instead of address ([#300](https://github.com/layervai/nhp/issues/300)) ([f70264a](https://github.com/layervai/nhp/commit/f70264a7ba8387c7ffa6009006dd98e78b5e1ffb))
* **ac:** use unconnected UDP sockets to accept server responses ([#298](https://github.com/layervai/nhp/issues/298)) ([d7000b7](https://github.com/layervai/nhp/commit/d7000b79bc74c82a402823444ee03a47a4552ccc))
* address code quality warnings ([#55](https://github.com/layervai/nhp/issues/55)) ([16eb2bc](https://github.com/layervai/nhp/commit/16eb2bc178304e72707dc83be0c847e3fbbf2793))
* **ci:** add checkout before composite action to fix local action resolution ([80ad231](https://github.com/layervai/nhp/commit/80ad2319d2d00fa4412b443fc7af172fe9c234f2))
* **ci:** add dependency hash to Docker cache scope ([#95](https://github.com/layervai/nhp/issues/95)) ([db39e17](https://github.com/layervai/nhp/commit/db39e1756fde4f4d62a4db9add330d97de113626))
* **ci:** add job-level concurrency to prevent overlapping deploys ([#185](https://github.com/layervai/nhp/issues/185)) ([c1be657](https://github.com/layervai/nhp/commit/c1be6574876aef77c32dc9b6d9773f65fb033b34))
* **ci:** add lifecycle hook permissions ([#141](https://github.com/layervai/nhp/issues/141)) ([0886d93](https://github.com/layervai/nhp/commit/0886d93ab22966fa695e511a388b61d98f37ea5d))
* **ci:** add pipefail to terraform plan steps ([#156](https://github.com/layervai/nhp/issues/156)) ([bceaa83](https://github.com/layervai/nhp/commit/bceaa839cdfc0133642fbd0e98db158332633cd3))
* **ci:** add RDS HTTP endpoint permissions to GitHub Actions IAM role ([#50](https://github.com/layervai/nhp/issues/50)) ([10191dc](https://github.com/layervai/nhp/commit/10191dcc26a07f6ccb8931cbfa48b0e397a50c58))
* **ci:** add trivy failure diagnostics to build logs ([#109](https://github.com/layervai/nhp/issues/109)) ([5e6fcb5](https://github.com/layervai/nhp/commit/5e6fcb54ba5d2a818ae73101342485c0d687f3b6))
* **ci:** disable SkipMatching for Console EC2 instance refresh ([#94](https://github.com/layervai/nhp/issues/94)) ([9ff90dd](https://github.com/layervai/nhp/commit/9ff90dd1a7041b499df88625c07211d90a2e4df8))
* **ci:** distinguish cancelled from failed in Slack notifications ([#51](https://github.com/layervai/nhp/issues/51)) ([686215b](https://github.com/layervai/nhp/commit/686215b5271e867b115360a417e42f566ce192af))
* **ci:** fix change detection and remove stale image fallbacks ([#306](https://github.com/layervai/nhp/issues/306)) ([0ff53b2](https://github.com/layervai/nhp/commit/0ff53b2cb16a6ba735f7f32c52a0bcf3aaf3ded4))
* **ci:** fix Trivy SARIF severity filtering and pin action to SHA ([#71](https://github.com/layervai/nhp/issues/71)) ([21c2ed9](https://github.com/layervai/nhp/commit/21c2ed993452ee546c76123511d97659aa420afb))
* **ci:** handle existing instance refresh in canary deploys ([#175](https://github.com/layervai/nhp/issues/175)) ([24ab320](https://github.com/layervai/nhp/commit/24ab32081c54feceb471a00421356d5de5271763))
* **ci:** handle Terraform ASG attachment migrations ([#97](https://github.com/layervai/nhp/issues/97)) ([4992fc0](https://github.com/layervai/nhp/commit/4992fc03bd8c32e9cfa17c0413beca6643b27536))
* **ci:** run canary health check only once during instance refresh ([#184](https://github.com/layervai/nhp/issues/184)) ([c9186df](https://github.com/layervai/nhp/commit/c9186dfc07d1b7c1b21e0efabe1951520af0c696))
* **ci:** update Go to 1.24.12 for CVE fixes ([#272](https://github.com/layervai/nhp/issues/272)) ([da73f12](https://github.com/layervai/nhp/commit/da73f128c91ee56aac533c290b8e9664ca1f84c3))
* **ci:** update trivyignore for Go stdlib CVEs ([#273](https://github.com/layervai/nhp/issues/273)) ([e9dbbac](https://github.com/layervai/nhp/commit/e9dbbacb43f9a418142cc5705f74e9b19eaead42))
* **ci:** use $HOME instead of ~ for TF_PLUGIN_CACHE_DIR ([#163](https://github.com/layervai/nhp/issues/163)) ([a02f2f3](https://github.com/layervai/nhp/commit/a02f2f3d15e7d71a9bd36f08cbf5b5a15788610f))
* **claude:** emphasize reviewing latest and all CR feedback in /cr skill ([#207](https://github.com/layervai/nhp/issues/207)) ([81d53b4](https://github.com/layervai/nhp/commit/81d53b411c232cd1bf81347a7f05808eb861c560))
* **console-ec2:** handle trailing slash in custom_auth_api endpoint ([#72](https://github.com/layervai/nhp/issues/72)) ([83257f2](https://github.com/layervai/nhp/commit/83257f21cea9bc00455d8826fbe7d20138e3c5f7))
* **console-ec2:** restrict portal domain to login-related paths only ([#70](https://github.com/layervai/nhp/issues/70)) ([d40275b](https://github.com/layervai/nhp/commit/d40275b2e4c60dc8ee2e92e737c4300337a37c55))
* **crypto:** add proper error handling for NewHash and AeadFromKey ([#86](https://github.com/layervai/nhp/issues/86)) ([5d98cf9](https://github.com/layervai/nhp/commit/5d98cf985cceb185ca29b06972957754ccc6de3f))
* **ipv6:** fix critical bugs in IPv6 support implementation ([#81](https://github.com/layervai/nhp/issues/81)) ([b652ca9](https://github.com/layervai/nhp/commit/b652ca9839b348d4234dff15a63fe3aa5fe8dcfb))
* **notify:** handle multi-line commit messages in trigger detection ([#182](https://github.com/layervai/nhp/issues/182)) ([f175cd8](https://github.com/layervai/nhp/commit/f175cd855bd527279ebfba672ea20fc72472f0b8))
* **qurl:** remove sync.Once copy in tests to fix go vet ([#210](https://github.com/layervai/nhp/issues/210)) ([a4aacfe](https://github.com/layervai/nhp/commit/a4aacfecdd66469ae55d41a0e13b76e57afe6d64))
* **qurl:** use wget instead of curl for container health check ([#269](https://github.com/layervai/nhp/issues/269)) ([da42d5d](https://github.com/layervai/nhp/commit/da42d5d4e6e405e4cdbbfac4f0f25c5d12ea6def))
* **security:** add decompression bomb protection and rand.Read error handling ([#82](https://github.com/layervai/nhp/issues/82)) ([ae97b69](https://github.com/layervai/nhp/commit/ae97b696c3aebee052c81dcb2170f3b663a8d9b8))
* **security:** prevent path traversal in httpstorage ([#52](https://github.com/layervai/nhp/issues/52)) ([7bd45b0](https://github.com/layervai/nhp/commit/7bd45b01ce64ec0d788027c23ef51a369f06cdb9))
* **security:** set HttpOnly and Secure on auth cookies ([#53](https://github.com/layervai/nhp/issues/53)) ([3900cec](https://github.com/layervai/nhp/commit/3900cecd88073883d8f8cc953e4f4fc61c49600c))
* **security:** sync upstream security fixes ([#80](https://github.com/layervai/nhp/issues/80)) ([aeed310](https://github.com/layervai/nhp/commit/aeed310d27576c0e5765ceb02a4f37d01a02f770))
* **server,terraform:** nil map panic and TCP health check for AC ([#234](https://github.com/layervai/nhp/issues/234)) ([6c5eeb7](https://github.com/layervai/nhp/commit/6c5eeb76bf8d9f19e8db7cb7e3ec6791c4ca9b31))
* **server,terraform:** server stability and Console AC improvements ([#240](https://github.com/layervai/nhp/issues/240)) ([908e66b](https://github.com/layervai/nhp/commit/908e66bb2a2d6b9bc25ec1514cbe6ce5e3ddedf1))
* **server:** add dynamodbav tags for DynamoDB unmarshaling ([#193](https://github.com/layervai/nhp/issues/193)) ([b38d336](https://github.com/layervai/nhp/commit/b38d336a3d96746d3ab46647724962cb2c6e151e))
* **server:** clean up stale AC connections on re-registration ([#316](https://github.com/layervai/nhp/issues/316)) ([a07968a](https://github.com/layervai/nhp/commit/a07968af28c8adf79ffa23fde9d223ebc17ad3f7))
* **server:** filter stale AC assignments using Cloud Map health discovery ([#199](https://github.com/layervai/nhp/issues/199)) ([d0b4f3a](https://github.com/layervai/nhp/commit/d0b4f3abe0d343d5d1682fe49c52876e4223ff50))
* **server:** handle CachedStorage name in DynamoDB health check ([#231](https://github.com/layervai/nhp/issues/231)) ([d4c0e9d](https://github.com/layervai/nhp/commit/d4c0e9da476294e2339259a2a593aa8f36d2e728))
* **server:** implement DynamoDB license validation for cloud mode AC trust ([#146](https://github.com/layervai/nhp/issues/146)) ([e9fadd2](https://github.com/layervai/nhp/commit/e9fadd2b05bff913c1e6f96c2a45aabd33c78d8f))
* **server:** initialize peer recvAddr in cloud mode registration ([#315](https://github.com/layervai/nhp/issues/315)) ([44bfae9](https://github.com/layervai/nhp/commit/44bfae98b4389fb097dd923e54a5c14aacff90aa))
* **server:** prevent nil pointer panic in AddACPeer ([#233](https://github.com/layervai/nhp/issues/233)) ([6f9b061](https://github.com/layervai/nhp/commit/6f9b061bf9236ad4d40fc593d59fcd0d6960295b))
* **server:** prevent nil pointer panic in updateResources ([#226](https://github.com/layervai/nhp/issues/226)) ([34089de](https://github.com/layervai/nhp/commit/34089def2d2ffca1cbf7875363fc3b6940b8541e))
* **server:** require license key hash in cloud mode validation ([#150](https://github.com/layervai/nhp/issues/150)) ([5a17099](https://github.com/layervai/nhp/commit/5a17099fbf971ee7ecf20f2a67371af0cc4faa79))
* **terraform,ci:** rename AC target group resource and run terraform before build/test ([#236](https://github.com/layervai/nhp/issues/236)) ([5a8ecab](https://github.com/layervai/nhp/commit/5a8ecab0b516432c83e45d847b9e799009898ce8))
* **terraform:** add allow_overwrite to Route53 records for qurl.link ([#330](https://github.com/layervai/nhp/issues/330)) ([9faf604](https://github.com/layervai/nhp/commit/9faf604b3c4a362487d00f20c0089b99f7aa2572))
* **terraform:** add API_BASE_URL to QURL service container ([#265](https://github.com/layervai/nhp/issues/265)) ([2345889](https://github.com/layervai/nhp/commit/23458895a22bc50fe84670cfd29b5125269a1320))
* **terraform:** add apt lock wait for NHP server user_data ([#173](https://github.com/layervai/nhp/issues/173)) ([2c29046](https://github.com/layervai/nhp/commit/2c290468bfe85c648b95003fff36a4e90146e0e8))
* **terraform:** add assume_role to route53_mgmt provider for cross-account access ([#329](https://github.com/layervai/nhp/issues/329)) ([e0a26ef](https://github.com/layervai/nhp/commit/e0a26ef052366c6fd3d616f401adc241ecaced3f))
* **terraform:** add CancelInstanceRefresh permission to GitHub Actions role ([#183](https://github.com/layervai/nhp/issues/183)) ([e21bb0c](https://github.com/layervai/nhp/commit/e21bb0c1aa1c69d164b796768424a3adaff2062a))
* **terraform:** add CloudFront and S3 permissions for QURL link ([#274](https://github.com/layervai/nhp/issues/274)) ([1923e06](https://github.com/layervai/nhp/commit/1923e067eef2d366f083a4c590587a54dd361705))
* **terraform:** add Console AC customer_id to fix startup panic ([#144](https://github.com/layervai/nhp/issues/144)) ([1adf068](https://github.com/layervai/nhp/commit/1adf068e80f5ecdd155789717246398c5624761e))
* **terraform:** add CORS allowed origins for QURL service ([#264](https://github.com/layervai/nhp/issues/264)) ([c97c998](https://github.com/layervai/nhp/commit/c97c998027f126927943c65e703b2c632eaf1e1c))
* **terraform:** add domain_name to QURL allowed hosts ([#268](https://github.com/layervai/nhp/issues/268)) ([83fc8d6](https://github.com/layervai/nhp/commit/83fc8d61e886772be91b8c77b345920da9944506))
* **terraform:** add DynamoDB and IAM policy permissions for GitHub Actions ([#121](https://github.com/layervai/nhp/issues/121)) ([ac06a76](https://github.com/layervai/nhp/commit/ac06a768a3cb988977c027ac146971a9a13cf36e))
* **terraform:** add dynamodb:DescribeTable to server IAM policy ([#263](https://github.com/layervai/nhp/issues/263)) ([ea0051d](https://github.com/layervai/nhp/commit/ea0051db4f2000178161eb3b183bfcc665e7c059))
* **terraform:** add ECR and ECS permissions to GitHub Actions role ([#251](https://github.com/layervai/nhp/issues/251)) ([366a596](https://github.com/layervai/nhp/commit/366a5960371b7b1f54f747938b9e2efab65458c5))
* **terraform:** add lambda:PutFunctionConcurrency IAM permission ([#285](https://github.com/layervai/nhp/issues/285)) ([6df007e](https://github.com/layervai/nhp/commit/6df007ea2abc476f288de657254a3d004525f4a0))
* **terraform:** add missing ASG target group permissions for GitHub Actions ([9d31a20](https://github.com/layervai/nhp/commit/9d31a20c9fc5e05cd4eb7f1524a65050a04db496))
* **terraform:** add missing qurl_container_cpu/memory variable passthrough ([#249](https://github.com/layervai/nhp/issues/249)) ([fa21cc2](https://github.com/layervai/nhp/commit/fa21cc2e3a8ea2b809f1313c66b672e6419d7ccf))
* **terraform:** add moved blocks for Auth0 module state migration ([06fabcd](https://github.com/layervai/nhp/commit/06fabcdc3319f028a400a87fa75762bb20d01675))
* **terraform:** add NHP health monitor config to Console EC2 ([#143](https://github.com/layervai/nhp/issues/143)) ([2e1a8e9](https://github.com/layervai/nhp/commit/2e1a8e9c160e29747679bdc6f35beefaf726af02))
* **terraform:** add qurl-router to traefik_plugins config ([#312](https://github.com/layervai/nhp/issues/312)) ([7985d90](https://github.com/layervai/nhp/commit/7985d9044203560de427dacd3360aef4ba5462ae))
* **terraform:** add resolve.qurl.link DNS and fix token regex ([#318](https://github.com/layervai/nhp/issues/318)) ([4371981](https://github.com/layervai/nhp/commit/4371981482de60cd2e2537ff31a85aa0045c68c2))
* **terraform:** add S3 object tagging permissions for QURL link ([#275](https://github.com/layervai/nhp/issues/275)) ([f68fc73](https://github.com/layervai/nhp/commit/f68fc736f089e0bb65c8a0401aba96cc59d9c655))
* **terraform:** add traefik_plugins_deploy_bucket_arn to sandbox env ([#206](https://github.com/layervai/nhp/issues/206)) ([1c227fd](https://github.com/layervai/nhp/commit/1c227fd291677274dc3fdd63370800d662ae1835))
* **terraform:** add traefik-plugins deploy bucket access to AC role ([#202](https://github.com/layervai/nhp/issues/202)) ([749857e](https://github.com/layervai/nhp/commit/749857e5ffe51ef8817ebcb59b186b6eeaaca9f4))
* **terraform:** add UDP 62206 NACL rules for NHP Server in private subnets ([#232](https://github.com/layervai/nhp/issues/232)) ([2d41cb1](https://github.com/layervai/nhp/commit/2d41cb1af2918f6cb06a7c7d27788d07179bb53c))
* **terraform:** add UDP ephemeral port rule for NHP return traffic ([#194](https://github.com/layervai/nhp/issues/194)) ([1eeff5b](https://github.com/layervai/nhp/commit/1eeff5bb588e90a7e507f4e359fed40091e88f90))
* **terraform:** align AC module AWS provider version with root module ([#74](https://github.com/layervai/nhp/issues/74)) ([37dc530](https://github.com/layervai/nhp/commit/37dc5305fed6d220711b8dc65ddc9c7416fd7120))
* **terraform:** align QURL AC ID with AC module default ([#293](https://github.com/layervai/nhp/issues/293)) ([65f954d](https://github.com/layervai/nhp/commit/65f954d190d0da067d087c809a995c9fd5424b96))
* **terraform:** allow browser access to QURL resolve endpoint ([#325](https://github.com/layervai/nhp/issues/325)) ([f1cccd7](https://github.com/layervai/nhp/commit/f1cccd7705144675057820af2515418da91c5f6b))
* **terraform:** always run nhp-acd on Console EC2 ([#137](https://github.com/layervai/nhp/issues/137)) ([a453d03](https://github.com/layervai/nhp/commit/a453d03f26822a2ed0a699e85fdb66ba4a308882))
* **terraform:** bundle Lambda dependencies with testing and best practices ([#281](https://github.com/layervai/nhp/issues/281)) ([46da555](https://github.com/layervai/nhp/commit/46da555e6f4016001d88cdd7bb59d2502cab5ca6))
* **terraform:** consolidate DynamoDB IAM permissions for table items ([#151](https://github.com/layervai/nhp/issues/151)) ([1c897a0](https://github.com/layervai/nhp/commit/1c897a0da5d2a95ac97d661b8f4f2b6710dbab64))
* **terraform:** convert CSR to pyOpenSSL format for josepy ([#286](https://github.com/layervai/nhp/issues/286)) ([01728a9](https://github.com/layervai/nhp/commit/01728a93348236e2c46ca57c8510314098822042))
* **terraform:** correct Console AC ID env var name ([#229](https://github.com/layervai/nhp/issues/229)) ([a4aee85](https://github.com/layervai/nhp/commit/a4aee85e12a97b0c7b50c64ef6a8c3d5ab8ded90))
* **terraform:** correct Console env var naming for Viper binding ([#230](https://github.com/layervai/nhp/issues/230)) ([ae2e04c](https://github.com/layervai/nhp/commit/ae2e04c5278f4d63f4857481833e129beec92a34))
* **terraform:** correct servers-per-ac env var name ([#136](https://github.com/layervai/nhp/issues/136)) ([f9d905b](https://github.com/layervai/nhp/commit/f9d905ba42b39dffde653199acbd1418802ab29f))
* **terraform:** correct storage.toml TOML structure for Go unmarshaling ([#195](https://github.com/layervai/nhp/issues/195)) ([399d47c](https://github.com/layervai/nhp/commit/399d47caf5605fc7efc0b085845734502f76d88a))
* **terraform:** enable qurl.site in centralized TLS certificate ([#307](https://github.com/layervai/nhp/issues/307)) ([280fb14](https://github.com/layervai/nhp/commit/280fb1469ca32e940510c75d619ef2ceca02372a))
* **terraform:** enable TCP health check for UDP target group ([#166](https://github.com/layervai/nhp/issues/166)) ([7b17bc3](https://github.com/layervai/nhp/commit/7b17bc3801441bf7134a4dfc3927b045d76ae11c))
* **terraform:** escape curl format syntax in template ([#172](https://github.com/layervai/nhp/issues/172)) ([1a51d63](https://github.com/layervai/nhp/commit/1a51d63adf992f2251c7303a84cae326880ed53a))
* **terraform:** fix acme-cert module deployment errors ([#279](https://github.com/layervai/nhp/issues/279)) ([4901075](https://github.com/layervai/nhp/commit/4901075426023b51b3736753c85202230dc925f9))
* **terraform:** fix Auth0 token lifetime constraint ([#257](https://github.com/layervai/nhp/issues/257)) ([759a562](https://github.com/layervai/nhp/commit/759a562c0ea55244cb3e17c4eaf9d363a16d9d9a))
* **terraform:** fix Console EC2 CloudMap namespace and service name ([#197](https://github.com/layervai/nhp/issues/197)) ([9e9a80a](https://github.com/layervai/nhp/commit/9e9a80a64d243ad0c97150e99e2a74d74e8ab730))
* **terraform:** fix IAM policy empty resource and user data size errors ([#222](https://github.com/layervai/nhp/issues/222)) ([291ee10](https://github.com/layervai/nhp/commit/291ee10253371a63e9b86899bf1a7aad54fee948))
* **terraform:** fix IAM policy errors for DynamoDB/KMS operations ([#132](https://github.com/layervai/nhp/issues/132)) ([b0e3cb3](https://github.com/layervai/nhp/commit/b0e3cb3b77fb85301127956a3717bfcd1fc681a2))
* **terraform:** fix malformed IAM policy in acme-cert module ([#280](https://github.com/layervai/nhp/issues/280)) ([10fb3f9](https://github.com/layervai/nhp/commit/10fb3f98644bf4a632a9d2c7ff3636882f101a67))
* **terraform:** force AC target group recreation for TCP health check ([#235](https://github.com/layervai/nhp/issues/235)) ([7339f45](https://github.com/layervai/nhp/commit/7339f45b0944d84b7d0ff3df23f28be0ac61d4bd))
* **terraform:** handle ACME ConflictError for existing accounts ([#287](https://github.com/layervai/nhp/issues/287)) ([d8696e2](https://github.com/layervai/nhp/commit/d8696e2f3fb398e7fb45d6e1ff500f21aa4200ac))
* **terraform:** handle ACME ConflictError for existing accounts ([#289](https://github.com/layervai/nhp/issues/289)) ([c4dd78a](https://github.com/layervai/nhp/commit/c4dd78ab9df434bcfb6a603aa51e9b0e4dba6596))
* **terraform:** health monitor uses HTTP check instead of ss ([#187](https://github.com/layervai/nhp/issues/187)) ([ed30d37](https://github.com/layervai/nhp/commit/ed30d379de09cce8cf2b820674f7c4b724ef8e21))
* **terraform:** include protected target group in ASG target_group_arns ([#96](https://github.com/layervai/nhp/issues/96)) ([c19020a](https://github.com/layervai/nhp/commit/c19020afbc225b4d5fb65a7a48409d2f068fc2d0))
* **terraform:** null-safe precondition, variable declarations, and validation ([#224](https://github.com/layervai/nhp/issues/224)) ([551ad7c](https://github.com/layervai/nhp/commit/551ad7c058ab61b7d0be04ac9aee51d441fd225f))
* **terraform:** only configure etcd remote.toml when storage_backend is etcd ([#225](https://github.com/layervai/nhp/issues/225)) ([618bc18](https://github.com/layervai/nhp/commit/618bc18d8a939f01ab22b10c2eaf89e0d3e8f140))
* **terraform:** pass CSR as PEM bytes to acme new_order ([#290](https://github.com/layervai/nhp/issues/290)) ([8594145](https://github.com/layervai/nhp/commit/85941451d8a812b9c4ba4ee86dbd5cf4b5fafe5c))
* **terraform:** pass deploy_qurl_service and add Grafana workaround ([#242](https://github.com/layervai/nhp/issues/242)) ([4f184ef](https://github.com/layervai/nhp/commit/4f184efe5f34fa4d66ec3db3cdcab7ef5be455eb))
* **terraform:** pass DynamoDB table names to Console EC2 module ([#134](https://github.com/layervai/nhp/issues/134)) ([6450a07](https://github.com/layervai/nhp/commit/6450a07c370105dff50b83afab0650381c0b2ae0))
* **terraform:** pass EC2 instance ID to Console Docker container ([#145](https://github.com/layervai/nhp/issues/145)) ([7eb1f62](https://github.com/layervai/nhp/commit/7eb1f625a1be9e38f327f371414c763b01117a2b))
* **terraform:** pass missing QURL variables to environment modules ([#267](https://github.com/layervai/nhp/issues/267)) ([9667c4e](https://github.com/layervai/nhp/commit/9667c4e8e4aa81be1b97d18e1c6d32bbd0056b6f))
* **terraform:** prevent 502 on Console when router/service conditions mismatch ([#142](https://github.com/layervai/nhp/issues/142)) ([91cc238](https://github.com/layervai/nhp/commit/91cc23870f46caebd3a82d521bf4c237c127ebbc))
* **terraform:** properly handle empty Resource arrays in console IAM policy ([#133](https://github.com/layervai/nhp/issues/133)) ([51c7eed](https://github.com/layervai/nhp/commit/51c7eed53e0ad4e814b88103ef611a8eda66e920))
* **terraform:** query existing ACME account for proper JWS signing ([#291](https://github.com/layervai/nhp/issues/291)) ([1f16f84](https://github.com/layervai/nhp/commit/1f16f84de38be02bdac59957b1d37ed1c050bcdb))
* **terraform:** regenerate Auth0 client credentials ([#270](https://github.com/layervai/nhp/issues/270)) ([afa2b3d](https://github.com/layervai/nhp/commit/afa2b3db53b1a70e8580e1b6a1ac446f60608b49))
* **terraform:** register qurl plugin in server_plugins ([#276](https://github.com/layervai/nhp/issues/276)) ([628747e](https://github.com/layervai/nhp/commit/628747e50dab08cd6e593b6bc26cb7314927f75e))
* **terraform:** remove deprecated health_check_custom_config from Service Discovery ([#165](https://github.com/layervai/nhp/issues/165)) ([890be5e](https://github.com/layervai/nhp/commit/890be5e8230ee5947830908b34064150e98982e8))
* **terraform:** replace deprecated dynamodb_table with use_lockfile ([#250](https://github.com/layervai/nhp/issues/250)) ([7971010](https://github.com/layervai/nhp/commit/7971010f2a1120df6be0499b7fd73029584c7cce))
* **terraform:** replace deprecated GuardDuty datasources with detector_feature ([#158](https://github.com/layervai/nhp/issues/158)) ([c65adda](https://github.com/layervai/nhp/commit/c65adda025949100f0786ed82f4d55a20a0a9ace))
* **terraform:** retrieve existing ACME account with only_return_existing ([#288](https://github.com/layervai/nhp/issues/288)) ([8ef9f03](https://github.com/layervai/nhp/commit/8ef9f0391d97a092cbf3279bee69675b566eea19))
* **terraform:** route resolve.qurl.link directly to NHP Server NLB ([#322](https://github.com/layervai/nhp/issues/322)) ([cb52110](https://github.com/layervai/nhp/commit/cb5211075dcaca26429e309d04e7dda40e1378db))
* **terraform:** route sandbox alerts to dedicated #alerts-sandbox channel ([#161](https://github.com/layervai/nhp/issues/161)) ([55b5963](https://github.com/layervai/nhp/commit/55b5963e340f687ad80096076d1748d54fb8a329))
* **terraform:** separate GuardDuty email alerts from CloudWatch SNS topic ([#168](https://github.com/layervai/nhp/issues/168)) ([5c1469f](https://github.com/layervai/nhp/commit/5c1469f9c8ae304413e6a5ca4e83c465a390fe08))
* **terraform:** Server storage.toml and Console IMDS hop limit ([#186](https://github.com/layervai/nhp/issues/186)) ([e9f09c4](https://github.com/layervai/nhp/commit/e9f09c49063bc2860f7c85280d17ab7831e3e976))
* **terraform:** set explicit health_check values to avoid AWS provider bug ([#162](https://github.com/layervai/nhp/issues/162)) ([68f6b4a](https://github.com/layervai/nhp/commit/68f6b4a28139af3184012f5fd0409a54ab7a7b58))
* **terraform:** support multi-value TXT records for wildcard certs ([#292](https://github.com/layervai/nhp/issues/292)) ([8fd4a70](https://github.com/layervai/nhp/commit/8fd4a703b289e86ef07d1eafb0e7a9edc2a48296))
* **terraform:** upgrade pyOpenSSL for cryptography 44.x compatibility ([#328](https://github.com/layervai/nhp/issues/328)) ([9ab1b6a](https://github.com/layervai/nhp/commit/9ab1b6a719ac266053c14cbdb01581a6de1bc001))
* **terraform:** use domain_name for HTTPS listener count condition ([6587b32](https://github.com/layervai/nhp/commit/6587b3267ed5961583d4cded79348857575309fc))
* **terraform:** use dynamic default_action for HTTP listener ([286a879](https://github.com/layervai/nhp/commit/286a879960d46368ebbd5ae920ae874a733f19c7))
* **terraform:** use ELB health checks for Console ASG ([#171](https://github.com/layervai/nhp/issues/171)) ([4fea030](https://github.com/layervai/nhp/commit/4fea03085c8a49aebfaedcb16551a0fc1c149c5a))
* **terraform:** use explicit image_tag instead of :latest for Console EC2 ([#157](https://github.com/layervai/nhp/issues/157)) ([2d3062f](https://github.com/layervai/nhp/commit/2d3062f9582174cefbda665a2d0ef86d018f3fe2))
* **terraform:** use HTTPS for qurl-router internal API URL ([#314](https://github.com/layervai/nhp/issues/314)) ([a38688b](https://github.com/layervai/nhp/commit/a38688b17fe248162a4dda6c8d5323efdce71331))
* **terraform:** use NHP Server NLB for Console AC cloud mode registration ([#149](https://github.com/layervai/nhp/issues/149)) ([d2461fa](https://github.com/layervai/nhp/commit/d2461fabca35a142106949ca28f4f0a8c36011d2))
* **terraform:** use properly quoted InputTemplate for EventBridge targets ([#164](https://github.com/layervai/nhp/issues/164)) ([a811e4f](https://github.com/layervai/nhp/commit/a811e4f428d6065f75d00abc9c6c1c27a8038c5c))
* **terraform:** use snake_case for Console AC secret keys ([#196](https://github.com/layervai/nhp/issues/196)) ([5c2cf42](https://github.com/layervai/nhp/commit/5c2cf42feeaea9356b4f40d991985b9634814355))
* **terraform:** use SSM parameter for Console image tag ([#167](https://github.com/layervai/nhp/issues/167)) ([b773f06](https://github.com/layervai/nhp/commit/b773f06816c65605e09e91d1fddd016f7326f1e3))
* **terraform:** use static Console AC ID for stable resource records ([#188](https://github.com/layervai/nhp/issues/188)) ([4a6dd06](https://github.com/layervai/nhp/commit/4a6dd063621f1d45e3d148b1ea12a770432b38e5))
* **terraform:** use URL-safe characters for RDS password generation ([#323](https://github.com/layervai/nhp/issues/323)) ([bf87e50](https://github.com/layervai/nhp/commit/bf87e50914c695cf72a18f6c47779ec5ee4c9a19)), closes [#49](https://github.com/layervai/nhp/issues/49)


### Performance Improvements

* **ci:** reduce instance warmup from 300s to 180s ([#198](https://github.com/layervai/nhp/issues/198)) ([b7929aa](https://github.com/layervai/nhp/commit/b7929aafa2accffde705f83af6c3ac4269169adb))
* **terraform:** speed up Console EC2 startup and health detection ([#191](https://github.com/layervai/nhp/issues/191)) ([45afc79](https://github.com/layervai/nhp/commit/45afc79566b99d166b20f3e3c8cfe9db55b9431f))

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
