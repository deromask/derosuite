// Copyright 2017-2018 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package transaction

import "fmt"
import "testing"
import "encoding/hex"

import "github.com/deromask/derosuite/crypto"

func Test_Normal_PaymentID_parsing(t *testing.T) {

	// this tx is from mainnet block 28310 txid fbb6bcc17c8095a22b27de99d1642eea2d84d0962ed9a4d09c68843fc19b6cf4
	tx_hex := "020002020005b5980a97218d7efa04f019080204624e07ed3970ccaa65a3bec936b7a2fdfec816ad91041d09a40e974b5a020005d5af098a1ee258df9001f122081aa173d99a5e2f402a88a409f25d055c3c4dd868de16d673f8938cc256e7fa020002973bc70a66899111da56c2d1710b169986888734c96e5a705a629fdabca6aab000026b73bdbd9a535ba28f169fbd704f223d1e9e3a6e2d09d862e6c69b88b0e245ad4402210084f42865552b22e95cf5c9b3cb2a2b5d52f7114b62a5bcf218fd2a5a41105f80018d92d0909fdfc65e676682a2683154f17b1b0061f6b927f073c760c78e8211f8028093dc81f8017045ee181a7a6cfb1d718d4bf87150740eab41944d402b3381e35123fce7b9c57130eb4a5ea9f0895ee622a689fd1a31a4bc2c76963d1b4b71fe371b539c26213774783a559cf8c0bef2d920a7c8b559f239979d31d02584c458a251b100690085199828c04b6fd563c49c1ab8a26b6a5bf28c1990864c2304b5f0349476c10e62e41d0a73aea2b46be34978450801624bb9ea6fee0239fe9ee8b77f67a86c0c56e8316571d0818b68a655d184f5036ed6b0793447bea98e5ba24536902d9c04ce43beed152c5f7a4a5a090ab3b823c37a71394805a9bbbee0492093b633466ba9e9aa85245e47459f0f2108801e09e3ab6fc29620036ba578b8d7cb59e099e14923020419a7743a324e9bc4f9a2fd74f03ae10b5bb10bdcb38a9fe5caacc8055b3883354b435f168a0a8e6bd1c9b3e1839eda3e145896ae331b2a7b894dbe08397ee6f737d12ebf7a104cea9b7ca1c1bfb8819fd1a4422b4051808c44794900d460f2e5b874ec579e2b883ce32c95462c28cc99dad05500bad5e54ef6442e0f2ef9903354287b5272be037c59ae212988d1c3d46f4e04ba534f7ed93f2d490891d4daff37a622ebdabfbde27ceaa4c05bc4280b5f3981040122e73c25cff30395dae7c8cb106f93c7917a697d804b4b4d86bf775221e7c89cacc7e75e90e40a6f860454e5161d824afa78a7c823340a74a513b5bfbc78c741f039c3ea381800a8b452bdc06c21a5eb6d28bdb6a108b0b542f0bab18f9752b2c21d1d502abc094f4769f4adf4a4b1159eba2cd2861636ca975827966ca57f4304bd39c9cd230a8cd66e06c80a1a10c1601c52896e596c56318f2dc619ea0e24f7446ba8ca43010504beef6c371e533acb36cc7e006a3a55e895d9b551d80d9769e7826edc2b0725a06ee0b75874fcd83fd94e4cf2bf2e2c836d6f9f44bfb8b88fbc0510c9f70287c75dda4bfff0fbd0ad327b4dc32b721602a06e8267e3813af1c47182bc580835de173b1de3064c0ba24384e1ef232d7a11892e8bb9b39b3888bdfa8915d600659d5c9ffb38ef9a5a90ebc19fe12b127faec510f8f5f1651100da265afdd307a9ae40a5f23b1ffcaa138a7c438347ad435625f6e3b082d56fe209461a99ea05a1e5f4b8dc722e4610dcc4daea6bf32a6f45e47c3f53ddc51dbdff0fab79b904e096f3e6e71701b242b74285bcfb371773bf619963db5c7b36fcb781a5d6eb00d8e5a9c5a8c6788a842c6347ab2bf0fc512071ecae16563c13496fc98536360b261c02f4478a9a53e2b17142f7e98a4eb0c4703639f28201a1c284deeee83801a513287af3240ce71c586cedc8d62c616bd01383b36ff51564470e0538a00d082289c05bec41a19db8a901d7ae86f7590b0f2a02c3c3738862c3303a3bf14807a1c375d6e1eb3d406ea3bc5f954baa9b64e285bcb81547c8f41f5c26c99de306c418888f132f2c3dd26ac9458f5aeb907faa820b70968598410f5d657dec1a0b681aef8d885cea5bd00bfb15bda08d705939257dbadadc5609e19e3ea20be10331fc21c448b794f76b8bb46412b3185296c7041779bec81f7a54fb4d1bc5220a725106f0986ee3fc74b1b88aa59d56b345976e819cf46dc32dcd5aebbcf6fc07a80503b1058ec0da64eb0479dfae96d4a289049d0688c487540a1f6f93a8fc0fb887bf21cff9c131f1774556d8175509e653683d63c28fcc2b2db7d0c49e680f215cda12ea2ba20db7763b6cd07443eb0bab075f9cbdc57944e75fc6dcd2470554ab12c34fe39f24f429ae79e6d9fae709959b2208038030bd14db6e50b9d2031f52ceb2267287a6a71715ca529fba088f447d49d33ab958f8ba225ef2637004db1b050eca6349cac367799e73ee102fea89827a66b04cc5ec1c5c483e622a05b681f4cec544a78d736b68287d299ec38c674579be41946402c69a6871b8650f3e7f7792ddac262a262328d823027a8af1ddccaf8685ab7c8fa9679fd68cd00a574ce3051011299a7ae169dca3ac2b70d92315ba596048f0d7d16998e988d6058d6770c2b6378a021ec79862fafe29a6d3873128ba68ab2089174e9a0f761b03f392c358f806acc6e9a33532efc62350695582831127d74bac28465ba380340206f01c653fbac50ae3e8516ae0f6c093f0cb7970d63a9ed223cef83fba38c70e9527db8e5b41c98c1b1269cb4af955ed64e53a6aa1a39e64e87818580d7fad02bc5a51789b19f40077a2ad00a96d34ed5b18b3e7b8b62c70f9e5ca99d10ff6014c0833c897121ea3e92bfba55cab6c097b3c033d936840c61134d6be8dd2aa023807411751d2d173d400fb50a93f03c8a192b1fd90d53d726748c592005f3c090911816f046f8bb91de516fe0025fc76c13962e9844d8789fd5d1b85a855820ac4f8577728b22d43a1a0e266609afc681fe396e4a6a588dc6867f5dbbdd396097a37bfcbe76500903e827d0cb411d105ab77361cbc09e2e4fcab77224002160c9d7dbd273757e7d1e9a19dc83c23c29fd3555b3994b0b012a31a06538861480a81c86f18b14ba42b2b0050a05984decca517ba5f4d6cc0dd258a2a6047c7c701c0da2a6495c8825f7bfb4c36d5b23d5e9bf99b88fddd6f9cd54763b9d1ac5d0ed534802a3a3df20cf9acb6a2ae5994cebad087ede848bbf1e2d622054bf2640bccd8ea5d29b86bcfa6c2878b5bbe2717bddb1a17cbad1318256112e089367a07b735aef0f72ca2d38eabf68402bc2b5d572d9c51c28f1ddfa305d0d6562b5b0d2be5e7503fdb76699f5611bb4616895fef1ce7a2c54fecbc60e863290e067b0499b43cc6f350cb7ffbf7fd21ee18d452156649c46aa7694c9242ee3a7466a00f66fbfd86abd75d73c430dd082cbb9808fa4c3a44bcc7378b8829b1d9bfc8e40117b547138904ac6e88679359411d3990d87d7fcbcec223f14bd44e85c4f3ae05af14d83e7122976860115240e6af323cd5bca19e71824022d500e461454aac04d5bfdfb8a6fe98d4c859ef0076f4a6ea845e8d588e792716e35a525ef61df0061d9c20f9104b1b4f5872ccfc73bfa7164b74dc647e90bb63db5dba3833cf4d0d6dba528c73c7d0af3e80797ee6b842c894a02700d8a3f5ff54e23e69165cea07c329e954c08d56b94ec3460323c79f8fb9e2bec66a2368a6981f9b027b37e206db95120e6a4e7577ccaf58f3865a1ddd0d865df6570fbc689e3fdcceebab5609f0ae2bb465e5c34650d914eae1cadaffb6d781ee79b7a4e34c5e6b2fbedb0e0c289d775e367e101c0f8c6e3350d46162a4d4cb4f8e4fe445bbfdf4f8f174dd091f39529e92db79b699f3996ca41be6f0af18d2fbc288ae7b6863d4d5e3a6a30af73050655097920c3a5eb7b79688c0e3c5b8491c83632903fba3ea57ca56240bee5e148d166f7181a669178f1fddfc99c3e3afcb4fa7c272d708d029fc681500c2b5ff908787725123d04331e5d87cd66fb79ff77852d25a09d6868482ad9e0fcfc3e99dca1f443b6480d076bb339780e74255462a695cdcd89e30537a9b5207c28765eb690d47dcf352ca1e1847070f697379e24c6b870fe843c127173a200ddd9006c21ba19d6725128476f7bbab2c8d7ea32614db6f4661c634e01260760ade3c10d07a412c7e315e5965e3dae24e35f4a369716e676450af72de90ed4b0a761778aba476eb26bb228bd82a667dd49afc5a27fa75415d2db8babf6e18020f67a53837adc0db4840343f94e1823a6c1001ac927fce7ce6d95a3fc6dc7aff01caadbc34c5317c6067a1314d50ed4ab2f9d31eb21865ac8b638c45a95219ab06bb7a145eafb5e0b1ae28122228754aba9a39c0925b8198d965fb74858e22db084e44561402718302e8cc6d9a8e59aa4688a6d93743a4969cc240251e488447052ed7c0aee2186c3a17c9096726e5c3e069042d151cc37ed9a938c355db3e660ccf44c1ec8f5ba10823072c5aa557a729c09fb9009447d6c7931076ac57f24f0e4624f48943d5525468cd990122250e54a4140c467fb7e8ca51388d17d3c6c60bed66fe3039e8687dc38f08a9d640d33d2b23d5bc6136b3ef8155557241174204e3e540dc0df75c0dee324e6ac2f97f89ad3fb99aeb7f0952f4d06e1d00eb67048317386071e4ff37d100927309c922fd1d4cfecf1a2174ba7d35d84cd6d552013204c525bf268490ceac49deab3906b11812863eb6b9aa57f2c78f118fec0c02a98693396a9ed03cb8dd697cfa74e22a06970371164ac057ee350a08dbdf0b0bf1a43a865ba69c00e8701fc7a2cc6d5bd3c26ba684eef53b220991ed05d94501e10ebafc2c8cb5a3e0862fa23b3e5e14fa5b58f1112131450aaaaa6caf1e430c527c2d08deefc32f5cf19a77807bc2a4e895652af568c7ec0b76ea2b9f167f0a382290e2f56b9998d103d8761a9a879856ae5ec44c648d142137f1e2473d2a08cd37e9fb544ef55665069e08d3281567448f347edad90edd8000169a3b0c5d03b275816a0080798e446ded04743f58b6891d72fba765ce93b0c95cfc6c3ebc08a6096a04ed06b4a92a02b2d40b96d26bd3b338249a142ea5f8f4f20ff3af12081e1fdb83400bce7ce40136c06865b54d93787264f85240297444c2c8e1645c0bf1a54ae71b94e26e494ee8cc02c734b4e037ad152dfcce013288f917991f270322890faa6fbc85412a1ff0abf1101fe19c47d45a8598b34a82e22219fc02a10f21cea47219568e7306d8357c3856a2168ce8e1e9831f551a679815a107218605eb4af547299b0ffbd63c23abafc3372fde284679be8c7ed923d9652b86c1050004992e7a859bbd60116d1ff45891f85b414f254b9649d9b1d5e0e1a7cbb84b025e93731a91cb1d1234d03b7ec02518d978853bafe4937d6570536704681efc05a10839949e23f29c23f8e60e66e6009a7d8d8447d0f793d6b763f5a5fb65e204fb6a7dca053a6a0468ce0943d941fcb32f2c9da3b8a4bd4eab0dfb083878ad0d6ba3ab4f81163b8e2fba448e45bad16c0bca6f29a3c2b07e601e39b041e5c505a7cc8a9e67e0ea4f722b4968b673d9e4551eeed29ab058dc3f8ad024c465b0095e912994f28cf3990f39965cb2231ef1995f5efd0cab01a124a6c181dc5640059b5f67c8d9002a84137da7ccb5f63636e640e2a9ed7aad396bf3ea4eb90739084d7ea0bf83467d31f037921d6f43e098f9dbbe9ba15aef5c92f6b1965c20850faa6e377c9b51570302ccc4402c57ea6e3decccd1d3f110fc955195a9553977029d7ad2db4359e5f6325f1fdf066f1a5ab1b84c6ac95ba09625293001660df708b747d605e08861310222fa21597ab1b5ca786eeec3f28871473262e2636d0b01469f7f17b8e5411af0d1ca2620427f4347e5a19ca53ba43176111d334a29af00cc97207110804fb4ee4f0f3f8891b311487b468795856a0364b14b83b8753d0a5c08271693c3318c2c06db4cecaa3d135786571d564eacf3f025775ee792a10cdffa43011dd73e38bff48ebea3b82c31da55abec25850fdc424ce52a5d9fe202218caee2b068448371a5e901879b8bf8b08576213625acf594caab14a8e1d80b69de944e3852cd0899b28a68b6767392681f583a914d21175eaf37e17a4d80027fa79651333371ad1a1a3a3afe9c3fca4e3aac364abc135d775a1a32f823be0347afc871fbcd2ebe39932c75586892023013cc09d2834916cbe195edea771a007d118d0936a767e243a94a85f5be9690d5895aeb23c8553b7c8ccf8d81217d0e035b021dca9f9e32e6b046f4dd569248f75e6db66c458524fc66377b6f0ad10e8dd7380eb5993ed18c5d0d4efaeffef86dd6ffe9277c26bcc2585c82f8501809b6b4a753844a13a1c76d7565151a4641914f218d274c9a9ccaf0f05aed910a0a91d84659355dfd9179e5abf57624ee9daca1fc49b36766e35437b5f04d7dee089d1d673692bad30333b6483e89c062bf452307ad2e1f90db1e7744c0dd6d7103b331b707193bf6e5e6b5081410cac39beb0eb932ac775f4f4c9918ee9aaef30eb12184da231b80afc9b7825676391384b762a0935d8a9a894bef6a8a2a3c880f1acfc71c51ed696565911f023dcc65f36ff4e47d9a271543940eca196ab50407f62f1e332f44e763dfd933f9da5f281a67a6651f27980f8f9e28b7361ebe3e0cacfeefad395d346a128ee748efca897c4a875cc1a1668a540b3fe4e29912040f5882df11860089c423d4ca5a12c40071d8cf17a1f5ee733234f804dc27f59a58d0b884a498ecd7ffe186265c2b4511152eb2d370434e7b1b8584f2fd16dfe9ee5586daf1542cb581028b6689eecf577340ff1186292700270956026d3adbbc68634f060427c1a64dead306abd7d9a1ce940c1581b45cfd9ae4e838ee6ee85e1e6b1ac87a93d5e17265492e2feedfa33f2724ad008328961c5cbbd7a295577f0bd42b49ec94dc24114098c44330345230df95ea6298c1508c33d15e4dbf5c37dff84873b0b564ba325844a63dd91447567faaa680a80ccacce9e84010dfdbfe293c34eecf0fb4d0f43880dfbcd3599e0b9f01bf7247a299a7ca650e46a1e193af4ee24ec99c5bf5409dc1f633fba132740c15406c58c85fafdcd4e2a212d21273c0bd4ecfe7da1aeee803a8e0ec4338953abba8827afb80b4198f99dd5cc7c579885986b833d63529d44c6a99e380e1642b8b6b9e224fb2646354a2c7c3d0d4a673a89b6401019fdb5ce34d35124492b754872c28e707e2d50ab5495430e84b20fcc9febb475d19e2dcd973cb15f51b8b43844fb835a18ab55a9488a86e82a74b3efa36d864f9278444a37e4c4239b98174cdf8b139a1dd7c2f5927df0eee57b4954707f46795a00e436c206c6b9813a02aaef8bb469e457a1e508200d531171f84d43b16421c542b01b6e0dc13cbd6cefc4d56a5ca045f9eb19af1859f87c6aa7e7bc584be4e302194c512ce320e09b1d7356bca08201b4adeb069d44f6e99f4960ab6baafd9e961869ab8d78c92bef22745bd5fb8c80d8d7e5479de7feb32295e66ed6600d75395c76195fe6fd844cc7fbe264b35b9726bc6c73f0e56e6144c0cd4897a6868e620fe44db448fb42b4fbd7d107226dd3eaaf07c43519861dfd22c00bfab42b7d2f1dec02699472fba2e8ef3778fdf2fbef7200caf9221154cac4b7890fbae36fb78ad4d6bba274100f875b5b1a7e913a9669a882ec066d20544e2f9ebd2871cea538b56c3cbdbc1cb784dba06bfd9c7664e7af33a3dec2c2d5f0cd254f9bf79e97ba63e042bee0dfe14e406802aa01fdc6505181a6240f74a86aa6632a99191dd26129d2c215e119b59cda4f3dfbc755cd802e8c74a0894000bc33f578b24400680990410e29548656a6c94e98016c982d0e87364d3b545ea1958afff89f72c6cf9a7fbaffcf4d4287776063572d7c0c1271f26bd1852dc37d8760ac57aa53394920eee33de076e66936e9e2e7d2088f2198778a1a7b4b8147dfaff0ddd89fe1156a9e1a9af43cf6215127c52707cd03edf93fed8bbef82e213cad59ea0fa25d0d92a6ddf5269615006fe076f082f55b9348373e1f174eee104cfa6201e66e4ded3b99dd2a4f1b7dc9750359743ed0302fa6285437a2955b6612ec81134612a0bb0df80845e5845beeccaba1997b8a38af92a69925b4b1600dafdfa61f589925ccccc363aae6e5d359c9452ba622b492b3e79765197c78d8c6e8364d63bef4f70b53e88808141e31e88f74723177ff403abfb20204d077d1fe57014dfdcfc82a7e3dffd6f2b1908fd23070488c932d694d909db55cdf739329e8c81eaa90ffee24f5ae33549332c663d35b96d76571f13c877c265f1caaffd5d6897c6f8235117b2d109af3a92e3e37b0756c9699883afd1f36877d7af0f44f945680603f5afa52aa2fe277ef7ac251aebae1b3fccd819728b287edea42b65c52b55d5dba5c344d7bd0dfa6d3e26166878b0d3aaf47adddb27a81e3d5e6a4e59c856f15956862ce999db405aa53bafaedae54535d80c28a0a697309085c5d8ff37113a5c6981a965abf3a7320fe70239108a51f6bbe6225cb4c4903a0ebbc4be7f66c4f84d7bc8c4f84db56e5800fd869a638dc745e9a34fe4a00bf7c594bd99204a68c8f8ec7b633b48ac81dbd25a85a1d42ce709d7624bd49ec7c96a544d597b259eda548ff026790544830d3665cd6f909ee1a4d7abe19ed2f9f9b4c6c2f1cbe7aca3508881ee0ecda188accce8279ab71477d3f2b1a3bfb7a3abb1aa260ffc205afcc1b7c19176cbfac23a3cdd9f50ffb6896744efba2446b97563d65e3c08b2aa770bd94ae8f258d0627bf1d0c9b6a5efc47e1c2572f7105e0704bfc7f1fa7e1a11763a1631d47fc05ae51ec462e45fd3380f38026befb65279ef2d9ee6d694022a8794f96bbd75e3955f2023b892caa9abc0f33c8273da07b68ff79cfba20738a6917092c14860bb623bc06aa214f9c30516055c723d4fe8c6fd5fef3b5351a31cf639eb58a5e8f89c9584ad97fd58ca81126cac9413c80aeca57f0e0a1a42a105ea65d36a88e5e7ee739b2b4f46dcd65f367d493b9c2dfa0d9d06c901d9370f39648d4420050ed115b18663c767ae53a1d747b1b6b421e4f3770858d0f7a672f17dccd1668e80ab270b345decabda72371e7162dc3c4d973dffcbd6840d1266ec9ecbc723989e85aad56dee1502ed8b8b126d0f1000453eaee43c59f22f897a9e4bbaf03804c2cab710d24b81e585978f34d80005de067d1a34a2876c95c20bf49343bc7722dbcdfa078582ce737b5e03b992f835a2d36834c019bcafe14010daaf63545290766026f3ac0b153d46a13f4949ec64f8768fb896e196387ea755e2a5f361401e084e051f65a57245efb98a46ab192e8d803657efef028bd785166b82b6d296568b63d36cbf1b88ddf3e437e3dcd1cda2f9e3eee570de3c8b3f5bfccff4535a206b970a0d8631e71e71cf976bf9f3e72bb75cec76caef0594f2bb31b97a10ebdce404cf2d8263decb9bba89037882eaee4f5d1fc7fb9091a5c8ee227c42c46d2528325358fc7f0e35fb3c567b39bc285d0db5ba572a5911f2b9028a0de31045b1858e7dece4dc4ceddfb083ad417c36c5a49031dc42e5dab92d6c5a6f4d7aa4b6e2628372856c93b0bb82ab254e1a324393c8d37fad27092c3c14117ac488ebc63996ee7cdf70375d6e1539b9cf68b1d98b43231470160a13fc711f2d26a4c697351f60633c7b6e14855d23ffa1719f9c6678da911ee70fca4ee7b1d61051691b733994162271beae246aa421fd25078cc50d9b8d1fe40d6d7d2446ca93075d452c5884a1aa52ab7ccdbcf44d0a0efcb452534d697bb501befe80ffa71b065d3f72746f98f2257c0432a6b229091b53114d095f2bbd520cc0545e5c2bce14ebec0000f737faeb37976ac4862613f96d6244e99d539425036ce5fd336ce249e751a375de99e561b4a0e944de2803daf5446d479e7147ee07731785b25b640155ea94fd6e179593d6e6918583b0579d6a8cf30eda0832510e71cdea8d853f3ded658e4cd7be4ed5876e6e4c5d63d23e3b6936637c70017106befe996ccc1f300e0946f1b90ed56f8a06cdb877fe1436b5c5009e57a2b2ef0a52209cba49631b525ffe7fe29f4c272cf3383fef25b061d8f7cd0620b6804f0ade71fe9e7a40fcc939aa3c57e01cb6a77816f49b8724c7350c2590ada0a0530a3f1ac67cbcac73c97a067f2216b550de333c368c31bab010b6661e05917c250ba44a91683ad86b94129f0c068352ac953c3793175a25afa1192676f290a9b208b5c83edc5d3f19f7740713b57f14c04a8eac191467c1bb029c5f9dbe6b14d40ab400599df02ce4d41f40a71e71e70ec99f7daa2f4548e1af53ed058c00ea990de52d1a07c18041a8d35fe8a710fd6bab8fdb1e7c8c5efe000efe4c341e00cd087da19f62e2db052441ecf1ad72ec0341346e9c24124aeacdbf4adc0ba5439c08227a4f43b0fbb907aaa85747c062cee71cc6eef21b29433169231fd13b289e092883f90246ea34c46fb5f8a8869f0aaba6ab0a69f13a8a6bdf2329e266f7110f8fe697e53a183f16bb8206f314a4d71a8c6ba39e4d5a9b1d0bc24889ca494a03fa66b18eb077c783a9b1b7bdf1189ac7dd49287f48a989c6d16c1205cbe95a019c9879e1db765c72765fcd7a65aa02c8ae26680dbc290b6eb5eebab250945a0884928706a5f1e9ccaf7325cf7c3fe806abdac965647552fe66fd78dc02a2fd05547b700eeaea055737baf99f2233e0d0d31bea6eb547d7abb16b5a7b67fd3e0ff40bbefaf1268d9d7a067f1d68c034924c6e895d8ff360b9709fef48edd3f8086084e81a4b0829d28fabd3d3c3b704773045a4826e60ae509dcb9144ca874c0610ab056b2b3b405224ad30f398d7f36bba1bc0fdea7d3851b231f6f0b946ab024bf06a252f31cd31cb7da805fca18c0ce953912c3ea12ba8a7ba82611b710b047c0cce9943761e52a8349f4010fdb2661f19219e16a93ce352924edcdfdda3036fde42b28c719befab514d7c1f9d0e1460a8459175e29899c61a31cdd16a4a07d51d59ffd5e4dfc1cba2e6264ec988d07afa49fbd4f266b96045f993250ef50b74490ec7e08e0c741471af4b53beeacf91930c90c52617c2726a0f290ccbd600d38bc645039b10736a34f4630178f0d5e7a051abc33bb10186af430f2bc28f04e715f221a1c39742fb0fe663ad8c96dc2bfcb70c9679d1f2acf1c36abe6c8c0be1f41df646ff6ef2e719312193a3b24a3a69b1062966d144b55618bce2c5bc06c20c921676676b246f915a6a00fac891936ffc4234d9e4912cba1f41cf862e054a101e9fb17daecaf3959fe755e3d3981dacc84b33f11c9ca7f6bdc338833006a07b12bfec2e143b99a116316593f3f7876a8ccd96345345dfdb43ed5de1e90ddd1a490319c91f57845e308795b96c95cd8ba94527f959d1c78b05465072840cd3face4d52f3b2ce9b11614c8659b5278f7bf8c018cffd471c0a3242af789306a918568b3b59999394f6032aed8f6a65c747801d23ed0add9b385179705e3e06cd6cdd280f7798af344c3703125dc96df029caac608716b200f4415432c8e00ededcb625a751890d1e6d60259e750ccd8162e5ff5071a7146eba5e3fa300c301c25729fe385f0c250df9026d85982d0484a75fcf2998ec4c11655a0eb148040abd8f6409ab040bb905e7db9a7aebec9d3fbc787b1449013ed3ee6f3701925d072348d5c7eef37bf232c3479a5133e92eec9c3b354d07ccb5be00e17910565801a9b0ccb0e476b3f3da9ca40f967da81fadbdae19291f7a1e4d314d798aea2d034a23949aa9373aa52d87512720cf3761c090542e0a695fe2d213d98be5f77d034b451fa36620f24f8ab89900bbb902ff0021f21e57e2189e5bf1aa408b35610b67620b38ea384cfbbe59b938e0fcf028211e5c337dcd354da8a52a3f3574360eed0b963fd7a3eb3ee9f68568860757091436284015acd92c95e9687cfede660be4bf8db404d408c3c5505df30ae60ee190ae7626c15799fed884e99d4ee23e0fb7b7385965449cf44e4a4dceb6e6a29d5ca8c4e72ba390a49c96aeea330f890f6e629774b08554cd690764832e3db44ef6281e01ab0575e1ed74cb4215cdfa0cf07ba4c9244fa85cbbc3d20e4a3ccba61298b33ab6a1c3836446dbd54827580b226755d897626d5c0af177e81da9631709fabc5797e97b33207999b9370fe006e0d07ff89a138ecfafce2fac8756e11d330736c5d0efb65599e0012b79f8780d336f634584a75d7bbc4f83322c8b4232a7a16ed4d1da4178ac0838ec1c682b0e6ad3e3572269b1bd23a122cba524f71d9de156890e63dc6d3c17a733d59acf004c56b0b0f3876f5a612b356a69f81888979ec712916128fdf2b77a810fd72e0df3c212708009affe1c88a9f2b82a13b7fae2e6223b534589981b78b0f9a9b50c14f67fcdbb7adb72fecc51cfa5f5e4c3672e319173c073937915c38ea99a7e0c9a73dca6fbd5673587edaa4b2048bd74eccbda1c46720253e898292acdfaac0fd7bdce8a234b6c2851df9f4ebfd99318645ad76a7120f3a98da0ef8e0f0b6509c286384754a7040f5cb660c868d68871d1b99db024f86417e864286983f4ed0f4d2453f0d75d21c48f242be6fcb18e4049772f89aa5db3cd9d101cf190c36f090b5c8bfdbe872bb1c54badd3961c2d8e3d8fa7a8c8c42423ccb895092e737804c4d908595285fe0765d1b703ea7171c13546ac29c9a487ec51cb4f42d1a2ac0796ecbbd3c21e486ab86df021268ccf7ca785e7f9ef655e68d888c635806c8b0454f2c50f24c497a59070774799a217a8c06a9a596833de217e1d09173957ee0cc0ada955240936e45d039f783498bb18ce192aedaa1281e7819f1195cb8ae80744456be26bcdcd286e04b516450c24d747d99b4b6f6595697135b29a08f86e0b26e26be2cfc1e9e754445abf3e4ea0aaa949a7fe7ac518e310b5bc3c746b2a09d2396df5e878f26c10fc74fd938b40a6f3b7de0e056fbbec444d8664e1e5630f80301bc6ff42ce180166e1d124949f2f20a632b9434057c926d27322db4d3c0c2f3a0f4471a6ad364a591c93f2af016d516be4be7ebc00446e035ec569f87f095a0b40e05b3ca880d881691228edd7e5d04f1ea1805049d8d773f14b1894cf07bc5be1f633e564540f32cad267d288c923d9e71a6ea118940acc87d02e2d2c0d89d891beba806d450d899c65ab25dda0e518b6cab358ae9463b2f5b42e0e910fd81edd0a659e416b0a8875a493ad345c9265aa2647c56b12efb596023dc4c00c9e58e378e811aa53af6bf6bdeabc415524d1359a92c97dd4d31d02e79ee9010808a7a8f7ab9737e6bf800c84e35575b346e2619f80ee5d8fc7adbc1fb95fab0b5ab261fa7771053a0e2dffb413d8bacf3d36118c031dd0334fc2d7817a79f808eb959094de10a8a91a54af6e08e0e11fb23c9d6589e99a0ee206c050ed88650d06642cd80b360ee88e5ae422d58f40865e133b5a58d3ebd063007eacc7d90c0a477b87af533e1f818264edba4985c19e6124ca917982217c61b151ba06aeed0b36a1243e786324eb9976a5e171e299db3c8c3b5776a18386756e95c911283a08352c5cfaaaf1fa091ac35fb4a32d9e97688dd1eb8cd3ab8a05ad1192f8c4e7013b616b2c42f24be9d08c594171d1f216e57eb6f9e1e2d16ef35a3ab847e95f03f47f4cf720568fa6dab31933143841379d38c0bb40a50b875e4013db8ca0ca0dbb23957418e2bbad4f2d784c9e236b05d29604c2c3c49dfd10a0032775f21d073f4f385c88d8c537f02d536e7214741001bb85aa3b82aae24198d1142a081d0209ba9d3455d0688e60f1f3598faa071b3202fd7eb037c20dd6ebf5c5a9e6e20495351a001a1661d3ba11274e778c2850804c30489523c995fa17e4ae0adb8c06ae29721f31860cb92a0c22443a648a6e2d26ac735b22494a43904d47eda721043b449522b01952ab1c579b4da846d424b14643c7ee2b4066aa7fb6a1ec6996034ede8817bee7160cfb858e237b5be3d18cda21a8b0baac1a9e7be72dc05cc90a663735fbfd473cb3c6c78e37fa67a7ff450cf29b6671b314781ff7a4235291045da35d2eee9dbc18100a3c2d272abf7bc3bd36f8180d007ad19833dd00864e0ba6f9678aeb78b43685db46861e215e67b502373988661407d53c99d907711806f3ed54a6b1bab528e1b619a23795cf3cd58d4d92c1aed264c73da23285e92c033072753cb775c53e7b4baea348559efc440941343539d9f6727918fb24fd590732d2623c210d44d4717f31b56d6f26838fd15a5020dca8e775672e37ce1a17096ceaa32bd6255dee0a7c6a1b786d5c769ec01c1740028020807f5d6f69368a092664e9bc9e6da898d7ad75c4cc9e78a55ab5d8be0efec685de7efeab926c820f6e5d898f6a9bc161b125b9f9c049d34b7d7f9bf9949bb9482def4f518251c30301052f3b5c78be0e4564752ef41460c0d3cbc1054b59b446f1ed2cb1e5654b08b43ff108e50c135bbc9d258363f0f9026ea0cf35d3253f20815e124d18661c0764ea23335c3066ba0b9e061f70f2b8c26dc2e28ac6650b3be964b8b4dc35a40d5f4bbec132e94833f2af4983a269b8546310482d8a294b3303246b800403f208d39337bca35ba0206e9f82de7b8ff76b138fb5aafac1082143a77ee0bbe265071313926768be99627dc786183dad192668d915e578bcf11e82aad889ccafdf06866e772a07719d7c83da19bc95ee4e5ffc7a214690daf43c4efcb98156cc970311cdb087873630d939be2ee63046650168b280f38c20334a184fe76f69e6d60db1f073afee9ede80705ee4a8c84480816cab4775dd5fbe55108080ed7e701c05caf4159ef2e45680a91aaf3aede46b5a8495573727543b5a84c9e482d1b0d707db5ab6ecee5bf00bcd3151d38914492a0cdf0db41a8a79bec00749caf6fc4a00c5646d7caddd97808b449e67643d840781763470c00806b09738c4ebdc0a2a04da6a742818a2f220c757b42657166235c7610ddeb19e06268d8dbad91263870b6987e9289001bb38f36efdaede7a8690189dfa7e6e5485f9cf161287a4502c08fbb83849c1d9dd88baad10b39ce521c95ae72aa892ffcaed265ac9e570d9f20b1b2c2f287b28c212a2b04639f0512d4cbb5bb9fe866687762ba43e04de454f0f273b2ea64d153dbce5320802fcfeefbcafcd07059642594e5a6322ceb81c5f0bda050ad07a613299e2f08e9c45b0f65af6374f372befc1d2ef9fb80796f4fd09f103d876cd2c12d8bbff385acb8737850133bcfdfd26aea7bd8ed73b34cb2709836946d90ccdee4a8cdb774fadc4519ae47143e535c29f88c5786ab3099d860574545ee45c9207df786c3f1f7e8b9dddaad996c6f0d2ef4de52da63adf1e15086391cf85c6ba73d22606918e9ac783a0cec5eebffa387f8d2c240069a66dbd5e3503c97bde9372cd08b0a6b7d61170214da4113268b7cdd6f96815fb2897823a8f3c4c2c7cf5ed9e60ab078c4a128181b5504aaf2667c1a781835f24f2d3e7bffb2eb5efce3da6d68877a5b35d97409a7a4c7a6167db275cb4a6bd62295f4ef52b5efb35d55cb227823aa7f873a010fb99923b741b7cdd17f8a80060e34f3712bc6095a6371b50b98addc1f5ab4985ff3a9a0e06b97497aee804fbe546b41ed28983bd7aad55266a2f18c80384e0d57606eca7fd73c12a3596831c690c36db8697ee5c470a5881ba3838596174aa02fbe7d4d9be92af4842b94771dd51af2ce1e1221a1e488e9a0ffea52d228b9d3825be53021c8040cb6a620470219e186a17249af4b85de857bf82e5bcd6bf1bed8c9521e244136cba0db2903394c791024afd9b06b64440ce9190c1782a4c6afc1aa37353ba02f40ee5e297af8916c01e4e89ebed8e5594dcfbf5c11ebfdd8c8b59ab1c247e67e9b17a9b4c41f945ce8961e3acbb6d0cd8611d278c801e3f42d2116749a0548d42e2aa88b03de29c9147b5f5c92d5de018cc85c21487f4fde679bf1fc2b10c07a58ae07775e4fe64080d697126e8afeddb8bbc10089c54fba52afb8c8c6097a1ef82a43dc3e39beac9fb9d19efbb8218c74784f5b08a16100dfb06fdccf48653c608e8e53d29dc220060afc1695d02e7f72884e33acbbdb03573dd069e958a0c95f4a72f3266142038598d1c02a83563dcf86459bcafaa8843fc1852348fe06d10bb04d16bb9c8118259d3dc4dac2296b9b15cf300049a42d6e46912e6e78651c04a38ec48f273ac0e436a25d48f012b4b416c03a26789865826123ac2e7a02972b938cfc431a8fbc49fb1b197c61fa561663f60aa3bec95f1ab0ac78ddafe1e3153cd952b570e6f4bffcfb06bd38ba83bd65b2a8ee39a2fb60cf614ea4895aa87ae2f1cf56a411e12c7b68796a009bfedf6cd71d59f8df287e1bc0c61d7284ce85bf5f8c87db2fe2a918c720bf18ba4e58a431bc3f2ebec11e836c2224e43068b5638cc3fbd771aa8ddfa0a80df4c4e667a241b65b676ac8e45c04731af239d3537a267ac5ddb23231282aa0d079aefccc03fbde6700fc27d3b2bbb7a0f19a7754a1beb6fa55ceebcb1ed2451d0515a09dfd563616b48120c7019ee10844106b649911ec1f260d428b9c9987bc5dc0406441e706c4fb0415faf79a54bd54a04f4ac5e98105da4cec66fdd54f66f06834ef0182a27191eeda3be67c651a33b3204508f63565da69966bcc5caeb21502d421219ba684eab4aad90e1c0cc74df4e81b8e5157331465742144b569a4472613421a670714eb3874faeaf7c622f003702ec1e3965e4e3dd9144256afdb16d7bfa73b572bd683115ee5b2931c9480c262350ed9e3643e76968fd27820a61e5f9b6bbefe813231dfd8560fdbe185ed99c9a3e8976c734afc07c514733326527c5647f3c2b0ef81b6e53972981f9cdc70967b1393aba3cc75398f3cdfe6ec3dc17e17ec4d2e69b6716f1355329e8e1c26e16fae48af03f3869913f4962217f7431dab7d2f1785dfa8c5ea2a05bc613e213b1f5b4627cd9dfd1470773290247ed5c784675eaf3aab0fab745fc05d3d06099ea04fc90168463c4e2ce56b4f09b8b0a6f282977ad0a58dff02275a086e24f75f65790bca2780a26bbb0f6cd96db527d07e73606e582997ff2e8e3c4cbc7748a09e4da1a5817048c5e811524646365d0b1e730f5ac3448bcea8e51a6823b10f00e07bffc3322e53c1c04ec61b4a27d0a7c48f5e92fe17a19b9d292a57fde9b53c544c357ed16965f648138b3952bd2fb4365aef4e35c6752f0ca476d04ea002961c1892c6e1d3973d878ecffd3e24895c2586bd20ab7f004b8ed108413b5b978a273ac65c6789f4a9024142b3821d01fc8af9882381a0389b69356ed9923fddca047080cc02b34bd37c8668f65877cc317bddf69f3c4a827921ebb31c3368ba3d631c6b9d8cbcb20e27863a60611e9b3f77f5c349fb9bbf8c088094a4a51e4730c5d09d741a34d6a7c7c7704e62c6f2edec2e8aa92a057a8874a4f61af1c0ba3baf214efe255a37feacde94ca17dbe45ecc34ef68fb617c5b4e463a335896c14f17347818c7c07af28967e615a4c27891e361b702ce53879ae911f3aca3a68cc3f38dddae243cb8092d32ce18668d6f878c86983418d6a71dacd2af545bbe5f3b59b2ada9e48efa7ada9d4dd6fc334422e7bf7638c9507d829852abf9f25b645a092030b1a3301c3af83a15a82462aed559d869525b9d1a9d29fa716645b30339ab333295a8a5d4049981a72efb26194afe0b67c9d5f95850bcb1e2edd792f86158b5f7c2d8c9037e917b6b339838491447109f23b81b5a6596f31d34aa3329993371805078d64df4846080b8d3a5eb74d5d60f0dc2f9809d501325bc78bfd4385145fa7d82f5261c1d9df2a0a96de729f995135625d9318ac7f6ab0ba52a2dde2cfa5ac7baa57c62b4a31af6d80e6e49bc5dce0a10c1ae01be4703e19159283886fc4c813a17c521e8ee89a34c1701e50e311c703bfde5e9f9c911da529cf515c47b146aa0a802ad98cd5345e1d7293db1dca994a32c3f5fb0b7eb2abe1ac3fa80b5f5247db93f8604addbae9c4beeb8065eb2cf7ae73e8f62312afd9da11c43f0374a0548055abb72bfb4b0b13dca204b0a8df50df272bffe0b1158837ca601d0501a2642bff00411db1a8664a34766824cc9f2d4b0cfcd4e0f0f2d34aae080f9e9230c658b574e31200ef19afc0974db14e6f96bfe108168f36daf0aa855942312c47c62ab73cdc21dfd446c0582ffa091f598570ef2f049fe79d5eebe404c80d2dff9c1b8ac640cdda9956c785fc2356fbf814ad13c02e652099a18216de049990e203159adb380a093dea775eacb5d21e5e9edabbc42e049ba0797eaea5a5290c94bc1139427481015beb8ea1ab1c3ac75d55c0bf8ebed6ed50b1f826a8b78b444ea0ce7721ce1103169f9a35bd69d46b1e919c13164219f632aed53205b819596c820d3c2e47d10c9d74d526948840a24993bc00feb0a8957b767760edf531ed53f70adc27b9b707da3b6ca19e79b18237d7050d8c11e4ec8d4f985707f1b610f04de28c50e74e0ef1bf3260c51eae9e241ec06e3c2f519019dd1c102c6451f085518a2ba057c6063ff69f2137f7b9af6f180a2415cd2517985ada99054b5320c262d47d5d060307c88b30dd9dd3318c9f79880f454fb4db2b18567dc612b808713c2ee1f06b3004b57538c012599f006f3f1999d8fb007d32c5062ea0b1b0de9d2034e9e9fb7b075c0cdaac6604d066a447f3216d77132cd47bf0e1b01cd21ba2ffabab3ef5660f817f10fd16d0531aceb009122074ad9cc1a8f855ce70ba50d63ae25417dc530eddacd160d13483a38ffb71b9aa723d84a461c5add598456199a39ef028f88901fd2111221ce003351480818e888a8d6ff1562e85b4ee35d421afe3a4c7ea790aea931b351836efaf0669fa7b52e820ecb969fae17cfd1889d1ad85364a68fd07918835a015ee915aea0f073cd6fba6461cafacfff1d7235bcaf2ccc0abdae803b11370466d43a8793553ce9301e9d279a48771020b74788433bf01ee2e905b072f3adaea02f2ba8384a05feafac71c8bf8aa03a25349cd23ae4b84285351fc085307d32043de1379bcea908a8edd14e787353ae240386dbb42936d20d6e00b0a387f9424e9257485c565783c45ed51e1a0acfa068bc4f6232882e0a95319420cb83ed64904eb4eb2ac04212fd8202e7e47f868eb8865266cddfb1ae2404f990fa5ab1d63912d16900df5fe000ca99be8d5037b55f50e4e95501c196c92a3c303"

	tx_data_blob, _ := hex.DecodeString(tx_hex)

	var tx Transaction

	err := tx.DeserializeHeader(tx_data_blob)

	if err != nil {
		t.Errorf("Deserialize fbb6bcc17c8095a22b27de99d1642eea2d84d0962ed9a4d09c68843fc19b6cf4 tx failed\n")
		return
	}

	if fmt.Sprintf("%s", tx.GetHash()) != "fbb6bcc17c8095a22b27de99d1642eea2d84d0962ed9a4d09c68843fc19b6cf4" {
		t.Errorf("Deserialize fbb6bcc17c8095a22b27de99d1642eea2d84d0962ed9a4d09c68843fc19b6cf4 tx  gethash failed\n")
	}

	if !tx.Parse_Extra() {
		t.Errorf("mainnet  fbb6bcc17c8095a22b27de99d1642eea2d84d0962ed9a4d09c68843fc19b6cf4 tx  extra parsing failed\n")
	}

	expected_key := crypto.HexToKey("8d92d0909fdfc65e676682a2683154f17b1b0061f6b927f073c760c78e8211f8")

	if tx.Extra_map[TX_PUBLIC_KEY] != expected_key {
		t.Errorf("mainnet fbb6bcc17c8095a22b27de99d1642eea2d84d0962ed9a4d09c68843fc19b6cf4  extra parsing failed, public key no match\n")
	}

	expected_payment_id := "84f42865552b22e95cf5c9b3cb2a2b5d52f7114b62a5bcf218fd2a5a41105f80"

	if fmt.Sprintf("%x", tx.PaymentID_map[TX_EXTRA_NONCE_PAYMENT_ID]) != expected_payment_id {
		t.Errorf("mainnet fbb6bcc17c8095a22b27de99d1642eea2d84d0962ed9a4d09c68843fc19b6cf4  extra parsing failed, payment id mismatch\n")
	}

	// serialize extra once again

	tx.Extra = tx.Serialize_Extra()

	// now parse it again and check everything is still all right
	if !tx.Parse_Extra() {
		t.Errorf("mainnet  fbb6bcc17c8095a22b27de99d1642eea2d84d0962ed9a4d09c68843fc19b6cf4 tx  extra parsing failed\n")
	}

	{ // test everything again
		expected_key := crypto.HexToKey("8d92d0909fdfc65e676682a2683154f17b1b0061f6b927f073c760c78e8211f8")

		if tx.Extra_map[TX_PUBLIC_KEY] != expected_key {
			t.Errorf("mainnet fbb6bcc17c8095a22b27de99d1642eea2d84d0962ed9a4d09c68843fc19b6cf4  extra parsing failed, public key no match\n")
		}

		expected_payment_id := "84f42865552b22e95cf5c9b3cb2a2b5d52f7114b62a5bcf218fd2a5a41105f80"

		if fmt.Sprintf("%x", tx.PaymentID_map[TX_EXTRA_NONCE_PAYMENT_ID]) != expected_payment_id {
			t.Fatalf("mainnet fbb6bcc17c8095a22b27de99d1642eea2d84d0962ed9a4d09c68843fc19b6cf4  extra parsing failed, payment id mismatch\n")
		}
	}

}

// manualy place edge cases, to see whether incomplete processing can be detected
func Test_Edge_Case(t *testing.T) {

	tests := []struct {
		name     string
		extrahex string
		expected bool
	}{

		{
			name:     "padding header only",
			extrahex: "00", // empty padding marker
			expected: false,
		},
		{
			name:     "padding data missing",
			extrahex: "0005", // padding data missing
			expected: false,
		},
		{
			name:     "public  data missing",
			extrahex: "0105", // public key data missing
			expected: false,
		},
		{
			name:     "extra nonce  header only",
			extrahex: "02", // only header, even length is missing
			expected: false,
		},
		{
			name:     "extra nonce  data missing",
			extrahex: "0205", // public key data missing
			expected: false,
		},
		{
			name:     "extra nonce invalid payment ID",
			extrahex: "020101", // public key data missing
			expected: true,
		},
		{
			name:     "extra nonce valid 32 byte payment ID",
			extrahex: "02210000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", // public key data missing
			expected: true,
		},
		{
			name:     "extra nonce unknown byte payment ID type",
			extrahex: "0221ff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", // public key data missing
			expected: false,
		},
		{
			name:     "extra nonce valid 8 byte encrypted payment ID",
			extrahex: "0209010011223344556677",
			expected: true,
		},
		{
			name:     "extra nonce unknown byte payment ID type",
			extrahex: "0209020011223344556677",
			expected: false,
		},

		{
			name:     "unknown tag",
			extrahex: "ff", // unknown tag
			expected: false,
		},
	}

	for _, test := range tests {
		var tx Transaction
		var err error

		tx.Extra, err = hex.DecodeString(test.extrahex)
		if err != nil {
			t.Fatalf("Tx hex could not be hex decoded")
		}

		if tx.Parse_Extra() != test.expected {
			t.Fatalf("Extra parsing test %s failed", test.name)
		}
	}

}

// manualy place edge cases, to see whether incomplete processing can be detected
func Test_Edge_Case_serialisation(t *testing.T) {

	var tx Transaction
	tx.Extra_map = map[EXTRA_TAG]interface{}{}
	tx.PaymentID_map = map[EXTRA_TAG]interface{}{}

	// make sure tx
	if len(tx.Serialize_Extra()) != 0 {
		t.Fatalf("Cannot serialize without key")
	}
	expected_key := crypto.HexToKey("8d92d0909fdfc65e676682a2683154f17b1b0061f6b927f073c760c78e8211f8")
	tx.Extra_map[TX_PUBLIC_KEY] = expected_key

	tx.Extra_map[TX_EXTRA_NONCE] = make([]byte, 300, 300)

	if fmt.Sprintf("%x", tx.Serialize_Extra()) != "018d92d0909fdfc65e676682a2683154f17b1b0061f6b927f073c760c78e8211f802fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("Extra Nonce Could not be trimmed and serialized properly")
	}

	tx.PaymentID_map[TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID] = make([]byte, 8, 8)

	if fmt.Sprintf("%x", tx.Serialize_Extra()) != "018d92d0909fdfc65e676682a2683154f17b1b0061f6b927f073c760c78e8211f80209010000000000000000" {
		t.Fatalf("Extra Payment ID could not be serialized correctly")
	}

}
