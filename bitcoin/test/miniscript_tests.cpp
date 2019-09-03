// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>
#include <string>
#include <vector>

#include <uint256.h>
#include <pubkey.h>
#include <core_io.h>

#include <test/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/miniscript.h>
#include <script/standard.h>
#include <script/script_error.h>

namespace {

//! 26 private keys generated such that both pk and pkh for PRIVKEYS[i] end in byte i.
static const std::vector<std::vector<unsigned char>> PRIVKEYS = {
    ParseHex("000000000000000000000000000000000000000000000000000000000004d44c"),
    ParseHex("0000000000000000000000000000000000000000000000000000000000009f0c"),
    ParseHex("000000000000000000000000000000000000000000000000000000000002224e"),
    ParseHex("000000000000000000000000000000000000000000000000000000000002fcf3"),
    ParseHex("000000000000000000000000000000000000000000000000000000000000ae0c"),
    ParseHex("00000000000000000000000000000000000000000000000000000000000095aa"),
    ParseHex("000000000000000000000000000000000000000000000000000000000000d9e6"),
    ParseHex("000000000000000000000000000000000000000000000000000000000001427e"),
    ParseHex("0000000000000000000000000000000000000000000000000000000000018f37"),
    ParseHex("000000000000000000000000000000000000000000000000000000000001aeca"),
    ParseHex("0000000000000000000000000000000000000000000000000000000000014c0d"),
    ParseHex("0000000000000000000000000000000000000000000000000000000000001d6d"),
    ParseHex("000000000000000000000000000000000000000000000000000000000002f91b"),
    ParseHex("00000000000000000000000000000000000000000000000000000000000027a2"),
    ParseHex("0000000000000000000000000000000000000000000000000000000000011dae"),
    ParseHex("000000000000000000000000000000000000000000000000000000000002568f"),
    ParseHex("0000000000000000000000000000000000000000000000000000000000017aae"),
    ParseHex("0000000000000000000000000000000000000000000000000000000000001e20"),
    ParseHex("00000000000000000000000000000000000000000000000000000000000150bb"),
    ParseHex("000000000000000000000000000000000000000000000000000000000001aab8"),
    ParseHex("0000000000000000000000000000000000000000000000000000000000003f08"),
    ParseHex("000000000000000000000000000000000000000000000000000000000000ddd6"),
    ParseHex("0000000000000000000000000000000000000000000000000000000000010d53"),
    ParseHex("0000000000000000000000000000000000000000000000000000000000002163"),
    ParseHex("00000000000000000000000000000000000000000000000000000000000255a7"),
    ParseHex("00000000000000000000000000000000000000000000000000000000000083fe")
};

//! Public keys corresponding to PRIVKEYS.
static const std::vector<std::vector<unsigned char>> PUBKEYS = {
    ParseHex("020fa064d7de6aca2fbe72250b048a7f20895498b53afe523c36d8919aabec4800"),
    ParseHex("02c16e26ec9c0de1124f010f8e82e3523438b107d69adef14d673146d6bbe1e401"),
    ParseHex("03c8aca3f54c909a624a3cb115af42a0fe6f6db9f6e9160f4c48a27ecca8591a02"),
    ParseHex("025dd8fa8f56a63e3a9e095b1d0f27afcb86d16f472447480685168847e22c0f03"),
    ParseHex("02649a4bd15861c3636bece34bf0ee0771bb663a53b7d5fc54f68e527f84379504"),
    ParseHex("03742c5ffa9aad0233455eb1d3b27b97f69757ae9848e68ff04d7ac16d2a05dd05"),
    ParseHex("03efe739680033fe7d2db9ab2cf7b4e4561863add1003244f645b5ab660275cc06"),
    ParseHex("03137f0d0e368bb6386f122771c47f797152fae0cf8a932eca2efc9e1363939407"),
    ParseHex("02fc0951ea9fb3ed6b5838daaca1d35b072e0b02f6eeb8e2e63cb44d4185a64e08"),
    ParseHex("037754e0b7b562b9ed1a4fdedad404a3463f06fa161b83c0c3f1c2b47a1b11e309"),
    ParseHex("022c88846f8cd26c20903a5bda70f07b576edb9b8e55ccb4aa31fe9a46d68e780a"),
    ParseHex("0248778fa9520b12a412d74b4765ad37a2695e37d64070d53c1e09cbd24c9f140b"),
    ParseHex("024f00660236ffd87144bc59b4e7c366dbe9e2adad6367d252c62d5b2f0e883f0c"),
    ParseHex("02b3a199fa015d2e397e42866e0419f17bdf5aa8ce960d4465abb32e773470250d"),
    ParseHex("023bbdffd73ff93225b2d2a829810d7b730c307f734113301c25b45604eee6b10e"),
    ParseHex("0327cbdc135c39f49955c44974350d005f725c9c5ff17080699007a3acbb07780f"),
    ParseHex("03c59488b4e0c393ba14e835455a77b93da4199429f98706804146a4f1a390cb10"),
    ParseHex("0248c74a768734fc6d3fccf7d1d4c1fa5973df97e5edd8d16b0b5d282400635b11"),
    ParseHex("02c39f2336c8e3a6c873a7c2411da61faec9cce263e67238d26ac144ec29006712"),
    ParseHex("0241638efc46b474e049678db72b8490d0ecfcc1394327a81e0108f070fe376213"),
    ParseHex("0265eab0df3753c3dd341abec0ce44b5b4ae64bdfedc6985245e07f555db32a714"),
    ParseHex("0263489be36e6c5106e952865a0e9e461e033d515b457f540c95e3123e7f838615"),
    ParseHex("03681d414b1e04f26facbe5d3c2ebc066b0d94a66787d50819c859db74326c0916"),
    ParseHex("03d0d0f8b79a04ac8eb6e010fa3608926f3b5bd886f84c361a8e1d9dd4b01ff717"),
    ParseHex("03ac11d6ef54ba9548853d938a639b6a6748ca6b3932092976b5d6524c5e665c18"),
    ParseHex("0332c93a8614cbbeeff69f2eb07fb15bff47f9a428f2f370e19a0523da2c488519")
};

//! Public key hashes corresponding to PRIVKEYS.
static const std::vector<std::vector<unsigned char>> PKHASHES = {
    ParseHex("2cef22ef5bc1c3c4310be12c86dc73f3b71c0100"),
    ParseHex("80cd15c4307362f6838657ff907c1136d77eb901"),
    ParseHex("e888d9bdb00a69ab52a995b72511d99de1cf7b02"),
    ParseHex("9b152f20298b5316919c43ded59d510b2a27dd03"),
    ParseHex("83c259d35c518208163cf977f44fb9ff765cde04"),
    ParseHex("314b8f101f8498b6822a8280ef4579930186c605"),
    ParseHex("eabc8a3274c04a3baf94e1704b1ecf5c41146d06"),
    ParseHex("ce528865b485cc0cd6cda9f25164c6be98791a07"),
    ParseHex("579886c525eb40808208f683366f60b1337c9708"),
    ParseHex("4eea2899b935dd2e8b01a8cddb26cb8cfc79d609"),
    ParseHex("c95b5887651068e6b5eec58c503aa4772c24870a"),
    ParseHex("3a31a4b2f7d405cb0691a47d20341932f85b2f0b"),
    ParseHex("72d54ea8b446b8b7eb0e752e670f504ee5bc660c"),
    ParseHex("b602a8b35bdd7090c36603144842b5add202dd0d"),
    ParseHex("931bd0dcfa899dde3f926cb2aed9c9cef64fba0e"),
    ParseHex("a76f1f8912318d964230e3af64daa279fd30c20f"),
    ParseHex("bd3ac708cf8ccb1f5df99c46fc3aa2f86703e610"),
    ParseHex("d9c90f00cd507062adfce16fbfe3f8813beb5a11"),
    ParseHex("42acb8072eba47a1bd30576d3ebc113042ef6e12"),
    ParseHex("02e858cd586d8d6e00d8df551dc2f1e5dacc1813"),
    ParseHex("ff9289e70af0442e8cda845c63a513cca3868b14"),
    ParseHex("010389480bafd54be9fa8b662031ae276a66c815"),
    ParseHex("0652d73a2d20be994a07dbb7019547701f661716"),
    ParseHex("dfa528bd7637a3572a849e172f8b6db287400617"),
    ParseHex("359aa5e7e1bc54bfb6b21edc0b7de2b52bd63718"),
    ParseHex("48688d7e321ed607792ef3d585e96d6185eda619")
};

//! ECDSA signatures on message 7 and PRIVKEYS as keys, ground such that the last byte matches the position.
static const std::vector<std::vector<unsigned char>> SIGS = {
    ParseHex("3045022100a5b64a9b3124d6c15629be6d93b5eab4f778ff252fedcb07f83e25b9f0931186022049964495ffd035948a3649ea8159cd6c0c66b9da05b19a34682cee3221effc00"),
    ParseHex("3043021f23d52e17e6a3605782f4d133a980be1ebbd99d58b7187b9da4f8c50f15888202207fb78bbe18cc2fb0e4aef267e37d87b818a5eaaf7102861a9d2a01b70f604601"),
    ParseHex("3045022100aa11b254ebcd33a2f1b86fdb4f0062e36c6f2bcd6d0cae6e048495d9f1f207cc0220578fb8b9ea106033e697e9fc093752c411754b8d54ca1f938096fd185519f002"),
    ParseHex("304402200a76941921df51a1d2d96da91791ea5138a75a9a6cbd824f855648e397d9c99702205cab5bc9858e6b8bc2d9177b6b726005733671c3a6685a2bfd9e4d9fc3160c03"),
    ParseHex("304402203347711ce2292bd3c610fb4dc406ccb841de164fb57f49f06fffb09d11a5926702202272de78e1bc96312d30f24a23231628e7e5d0fee5cc38e7616a64070d085104"),
    ParseHex("30440220257e07ac6ed035dec4d523e3637f911bb73aef591a09a264d018b82857bda34e02204cee5e2b8b45a6fd4e6f5328d2723ec2e040490f2647764f29fd587489fbe205"),
    ParseHex("3044022039a45e267f0872038bbaa855bafc2ad083bdb9eab05d50b587ee581c555017b8022043dfe7ac541708fec3d166e8ff5a15c484df55f6b74ca836b12a6533bc643d06"),
    ParseHex("3044022078653ba0bedc1ad061f06fd66b5aa6bfe56eaaba72205aaebd0e2df6294166cc022014c96758174453f4546175f29e0e8721a81b5252a344c7625f90c00ee23dda07"),
    ParseHex("304402202977382848852c8691a7c74b8b637bd5095f6e3041b1e27cb19457098f884e53022029770b67bf129118e470b93cd0269ea4f4638ea8acc0627d52aed938625d9408"),
    ParseHex("3045022100ebd15cf861473d85231501c6c68efe1a90cf30992323ae42ea1462b0490e04bf02200cb0f1553d35c4df9932df3f29c1194d692bb8a65ffb974a65017dd3b15e8209"),
    ParseHex("3044022070dcd9a4fd6f47408b9c06c387186466e5f2f42349e50e7ee146ec315d6a35e602202d0a48ba9da7fb599c4ecac0bd5c7560f16546dc9a1b4f9de5b1c490b6b15e0a"),
    ParseHex("3045022100ffb01b079b881c78e4e3a6549b1a0564f1877eb92a22d01a0efbfcbf043f783b02207cadbd7c9c257d91a6aca4ac21e2787b4b1843b6f9a984c84659dbe31bf0e60b"),
    ParseHex("304402202bd0c2fc7d94b9fbb6e500d5799e08fb0c274c9d5a4c463b734509afeca219ba02202cf4cea3c18a977beecfba2757c3f09a643e9c62b1a63c9de506320116e9b60c"),
    ParseHex("3045022100b09ebc0668cb9552d935252adfcbcd27277f1ec1d034277f2a83ead36fee8c13022020a060eac7dabee9305631b0e95f9466948d20f5aa1ec41d2c722b29a516640d"),
    ParseHex("3045022100f1acfd0ccbe7979ac7bfdd03254b21e79018c0bffa5101c1af82f5a81a0aec3f02202df8e5ac76970afd294ff5b4a2bcf1db86ca456431406cb9f38dc0ebabf6b60e"),
    ParseHex("304502210096937123831320343162bbef0563f5706faf81f653ba7038dec8ebd25583fb9002202a62cc29bbc745333132bb03901dcc3a9b148617ee1b530dca852899137a060f"),
    ParseHex("304402206f2be00b52ed430141becf8d3057b92d5401eb01c44ce2868be16d5017429007022011efbb1de520358acbf964735a4621db7a932a8c6a829fd65ef0a12ac3613010"),
    ParseHex("3044022060f07848069ad918687acaf90086370c66b04baa6ee53763e76624deef1ab03302205560869f76293557ffa26bc040e95d7a88101c6fa01bb9420ee53d8a42d09f11"),
    ParseHex("3044022006cad0d27bb5777efedcde481ff7b208b74a77e42afcf5f1cab57525a33baeb402200d2c02949d89836e0795853a4a8800d4c531a329eec1964ed1ecf7b6d00e0712"),
    ParseHex("3045022100ba01c4f59f3788d9e09217d0e8cca20f9f51451a216d64e913bbac85934991a702203898e6ca9a8eb46c26fa299cea7acd52f51d849a5deffa1fe19bbf2e6c922313"),
    ParseHex("3045022100b319cd340da44dbaf33363da9a97fc8958c4cb0407b09631144b04186de9507d0220755100641791ca9103e84aaf10be9a88007bbd143f5348e56dd0501a7209ac14"),
    ParseHex("304502210096d2bcda82a592eb533d95616038a267f43ec88f9a8ef4c62629df764a2f2fb80220728e852c1c34288c182dd6e0c0790b906b397337fb892366182289ca9d5e4815"),
    ParseHex("3044022034efd682a2688e224cea777127b20b5cc488c0a68ad2bd20ed0d30694537c614022044979a33f56890e7d7fc69a3d9ef2ec4c6e84844d7dc1a487f20636d9359af16"),
    ParseHex("304402207dc0f48445d7c65bcee7c441ac6040d0af9481a176754d05c836a8031343c62702205e07aac67acc0f8519100c536dcade6af48d4f2b94fe6e8d971e1f63ccda0117"),
    ParseHex("3045022100c100f8e760539ed4ddaa8fa37e84833331d3bfe8990622822ea54e9f21ed26cb0220475ed3f3bd513a87d5c713ae0330f38b5aed38859a0c26e6d255057188189818"),
    ParseHex("3045022100982b9947c862ac5454b9daffcfd8112854918b34cdf5791b14e1e0ba4eea13f502204f1fbeccdd9b45770933857e9e8bf2d531a05dc6237c203c94d14b210c607119")
};

//! SHA256 hashes for all \x01s, all \x02, ...
static const std::vector<std::vector<unsigned char>> SHA256 = {
    ParseHex("72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793"),
    ParseHex("75877bb41d393b5fb8455ce60ecd8dda001d06316496b14dfa7f895656eeca4a"),
    ParseHex("648aa5c579fb30f38af744d97d6ec840c7a91277a499a0d780f3e7314eca090b"),
    ParseHex("9f4fb68f3e1dac82202f9aa581ce0bbf1f765df0e9ac3c8c57e20f685abab8ed"),
    ParseHex("f849d67325facf04177bc663b2dc544051831c589ef581d412f2eba44834e77c"),
    ParseHex("e802086ad6a1e16b78352ad7296d2aabd835b1b16dbe951e1135b97c68e29d81"),
    ParseHex("4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0")
};

//! RIPEMD160 hashes for all \x00s, all \x01, ...
static const std::vector<std::vector<unsigned char>> RIPEMD160 = {
    ParseHex("422d0010f16ae8539c53eb57a912890244a9eb5a"),
    ParseHex("e8742ef70e66dd34014e45b847d923eee48b2403"),
    ParseHex("7dd7f871ad14950c1933f65611df24e9ae02433f"),
    ParseHex("467a5fcc05787ffa9ba8d20a5ff732e2af97fcf4"),
    ParseHex("184f0bc2046b560ad6b6b6180726d023a2ff3987"),
    ParseHex("d8e89e39976db5cb67eee655cf264dee79fe2831"),
    ParseHex("8a82f7562a7b7c9beca3ae2a43ce1080b2457039")
};

//! HASH256 hashes for all \x00s, all \x01, ...
static const std::vector<std::vector<unsigned char>> HASH256 = {
    ParseHex("a0d4a0b8484643488c45836275bdcf2ca1bf542239aa6ba72bbc5a5951cfb044"),
    ParseHex("328674a5f838f6987ead31003978b5ed607ccc5ed2aa73677f861d4d4e567cfc"),
    ParseHex("f517c428914b046c432b1d1927ac580d60e8b70d328c84c1b8c43231d8871721"),
    ParseHex("dd7d672fd9b45a8398cc7500aa119b9be8d0216adbf85c7fca919773aee4ccea"),
    ParseHex("be3246b46eb9c831ad5d1827c115be0c8fd6502e81156b695a522df5a6e4e99c"),
    ParseHex("ec0559ed29d75015de872db78428bb8110c45cb1fffaee3baa35f5f66b6b4bc1"),
    ParseHex("eb60bdee05596734335a93786236c2df6642b9f2730ff30e5242e6d4c1f3fec1")
};

//! HASH160 hashes for all \x00s, all \x01, ...
static const std::vector<std::vector<unsigned char>> HASH160 = {
    ParseHex("4b6b2e5444c2639cc0fb7bcea5afba3f3cdce239"),
    ParseHex("b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d1"),
    ParseHex("8a486ff2e31d6158bf39e2608864d63fefd09d5b"),
    ParseHex("18bc1a114ccf9c052d3d23e28d3b0a9d12274342"),
    ParseHex("2002cc93ebefbb1b73f0af055dcc27a0b504ad76"),
    ParseHex("6bb11f2db4784a6232da9fcbd178324a2779865a"),
    ParseHex("b566a3eecce809896361988823cd2f423fe800e7")
};

//! A simple Key abstraction for testing Miniscript. Each key is represented using a single uppercase letter.
struct TestKey {
    int c;

    TestKey() : c(0) {};
    TestKey(int x) { assert(x >= 0 && x <= 25); c = x; }

    bool operator==(TestKey arg) const { return c == arg.c; }
};

enum class ChallengeType {
    SHA256,
    RIPEMD160,
    HASH256,
    HASH160,
    OLDER,
    AFTER,
    PK
};

int FindHash(const std::vector<unsigned char>& hash, ChallengeType chtyp) {
    const std::vector<std::vector<unsigned char>>& table = chtyp == ChallengeType::SHA256 ? SHA256 : chtyp == ChallengeType::RIPEMD160 ? RIPEMD160 : chtyp == ChallengeType::HASH256 ? HASH256 : HASH160;

    for (size_t i = 0; i < table.size(); ++i) {
        assert(hash.size() == table[i].size());
        if (std::equal(hash.begin(), hash.end(), table[i].begin())) {
            return i;
        }
    }
    return -1;
}


typedef std::pair<ChallengeType, uint32_t> Challenge;

struct TestContext {
    typedef TestKey Key;

    std::set<Challenge> supported;

    std::string ToString(const TestKey& key) const { return {char('A' + key.c)}; }

    std::vector<unsigned char> ToPKBytes(const TestKey& key) const { return PUBKEYS[key.c]; }
    std::vector<unsigned char> ToPKHBytes(const TestKey& key) const { return PKHASHES[key.c]; }

    template<typename I>
    bool FromString(I first, I last, TestKey& key) const {
        if (last - first != 1) return false;
        if (*first < 'A' || *first > 'Z') return false;
        key = TestKey(*first - 'A');
        return true;
    }

    template<typename I>
    bool FromPKBytes(I first, I last, TestKey& key) const {
        assert(last - first == 33);
        if (last[-1] > 25) return false;
        if (!std::equal(first, last, PUBKEYS[last[-1]].begin())) return false;
        key = TestKey(last[-1]);
        return true;
    }

    template<typename I>
    bool FromPKHBytes(I first, I last, TestKey& key) const {
        assert(last - first == 20);
        if (last[-1] > 25) return false;
        if (!std::equal(first, last, PKHASHES[last[-1]].begin())) return false;
        key = TestKey(last[-1]);
        return true;
    }

    //! Implement simplified CLTV logic: stack value must exactly match an entry in `supported`.
    bool CheckAfter(uint32_t value) const {
        return supported.count(Challenge(ChallengeType::AFTER, value));
    }

    //! Implement simplified CSV logic: stack value must exactly match an entry in `supported`.
    bool CheckOlder(uint32_t value) const {
        return supported.count(Challenge(ChallengeType::OLDER, value));
    }

    bool Sign(const TestKey& key, std::vector<unsigned char>& sig) const {
        if (supported.count(Challenge(ChallengeType::PK, key.c))) {
            sig = Cat(SIGS[key.c], Vector(uint8_t(1))); // Add sighash byte because why not.
            return true;
        }
        return false;
    }

    bool SatHash(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage, ChallengeType chtype) const {
        int idx = FindHash(hash, chtype);
        if (supported.count(Challenge(chtype, idx))) {
            preimage = std::vector<unsigned char>(32, idx + 1);
            return true;
        }
        return false;
    }

    bool SatSHA256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const { return SatHash(hash, preimage, ChallengeType::SHA256); }
    bool SatRIPEMD160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const { return SatHash(hash, preimage, ChallengeType::RIPEMD160); }
    bool SatHASH256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const { return SatHash(hash, preimage, ChallengeType::HASH256); }
    bool SatHASH160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const { return SatHash(hash, preimage, ChallengeType::HASH160); }
};

class TestSignatureChecker : public BaseSignatureChecker {
    const TestContext *ctx;

public:
    TestSignatureChecker(const TestContext *in_ctx) : ctx(in_ctx) {}

    bool CheckSig(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& pubkey, const CScript& scriptcode, SigVersion sigversion) const override {
        if (sig.size() < 2) return false;
        int idx = *(sig.end() - 2);
        if (idx < 0 || idx > 25) return false;
        if (sig.size() != SIGS[idx].size() + 1) return false;
        if (!std::equal(sig.begin(), sig.end() - 1, SIGS[idx].begin())) return false;
        if (idx != *(pubkey.end() - 1)) return false;
        if (pubkey.size() != PUBKEYS[idx].size()) return false;
        if (!std::equal(pubkey.begin(), pubkey.end(), PUBKEYS[idx].begin())) return false;
        return true;
    }

    bool CheckLockTime(const CScriptNum& locktime) const override {
        return ctx->CheckAfter(locktime.GetInt64());
    }

    bool CheckSequence(const CScriptNum& sequence) const override {
        return ctx->CheckOlder(sequence.GetInt64());
    }
};

static const TestContext CTX;


using Node = miniscript::Node<TestKey>;
using NodeType = miniscript::NodeType;
using NodeRef = miniscript::NodeRef<TestKey>;

template<typename... Args>
NodeRef MakeNodeRef(Args&&... args) { return miniscript::MakeNodeRef<TestKey>(std::forward<Args>(args)...); }
using miniscript::operator""_mst;

bool Satisfiable(const NodeRef& ref) {
    switch (ref->nodetype) {
        case NodeType::FALSE:
            return false;
        case NodeType::AND_B: case NodeType::AND_V:
            return Satisfiable(ref->subs[0]) && Satisfiable(ref->subs[1]);
        case NodeType::OR_B: case NodeType::OR_C: case NodeType::OR_D: case NodeType::OR_I:
            return Satisfiable(ref->subs[0]) || Satisfiable(ref->subs[1]);
        case NodeType::ANDOR:
            return (Satisfiable(ref->subs[0]) && Satisfiable(ref->subs[1])) || Satisfiable(ref->subs[2]);
        case NodeType::WRAP_A: case NodeType::WRAP_C: case NodeType::WRAP_S:
        case NodeType::WRAP_D: case NodeType::WRAP_V: case NodeType::WRAP_J:
        case NodeType::WRAP_N:
            return Satisfiable(ref->subs[0]);
        case NodeType::PK: case NodeType::PK_H: case NodeType::THRESH_M:
        case NodeType::AFTER: case NodeType::OLDER: case NodeType::HASH256:
        case NodeType::HASH160: case NodeType::SHA256: case NodeType::RIPEMD160:
        case NodeType::TRUE:
            return true;
        case NodeType::THRESH:
            return std::accumulate(ref->subs.begin(), ref->subs.end(), (size_t)0, [](size_t acc, const NodeRef& ref){return acc + Satisfiable(ref);}) >= ref->k;
    }
    assert(false);
    return false;
}

NodeRef GenNode(miniscript::Type typ, int complexity);

NodeRef RandomNode(miniscript::Type typ, int complexity) {
    assert(complexity > 0);
    NodeRef ret;
    do {
        ret = GenNode(typ, complexity);
    } while (!ret || !(ret->GetType() << typ) || !ret->CheckOpsLimit() || ret->GetStackSize() > MAX_STANDARD_P2WSH_STACK_ITEMS);
    return ret;
}

std::vector<NodeRef> MultiNode(int complexity, const std::vector<miniscript::Type>& types)
{
    int nodes = types.size();
    assert(complexity >= nodes);
    std::vector<int> subcomplex(nodes, 1);
    if (nodes == 1) {
        subcomplex[0] = complexity;
    } else {
        // This is a silly inefficient way to construct a multinomial distribution.
        for (int i = 0; i < complexity - nodes; ++i) {
            subcomplex[InsecureRandRange(nodes)]++;
        }
    }
    std::vector<NodeRef> subs;
    for (int i = 0; i < nodes; ++i) {
        subs.push_back(RandomNode(types[i], subcomplex[i]));
    }
    return subs;
}

static const NodeRef INVALID;

NodeRef GenNode(miniscript::Type typ, int complexity) {
    if (typ << "B"_mst) {
        if (complexity == 1) {
            switch (InsecureRandBits(2)) {
                case 0: return MakeNodeRef(InsecureRandBool() ? NodeType::FALSE : NodeType::TRUE);
                case 1: return MakeNodeRef(InsecureRandBool() ? NodeType::OLDER : NodeType::AFTER, 1 + InsecureRandRange((1ULL << (1 + InsecureRandRange(31))) - 1));
                case 2: {
                    int hashtype = InsecureRandBits(2);
                    int index = InsecureRandRange(7);
                    switch (hashtype) {
                        case 0: return MakeNodeRef(NodeType::SHA256, SHA256[index]);
                        case 1: return MakeNodeRef(NodeType::RIPEMD160, RIPEMD160[index]);
                        case 2: return MakeNodeRef(NodeType::HASH256, HASH256[index]);
                        case 3: return MakeNodeRef(NodeType::HASH160, HASH160[index]);
                    }
                    break;
                }
                case 3: return MakeNodeRef(NodeType::WRAP_C, MultiNode(complexity, Vector("K"_mst)));
            }
            assert(false);
        }
        switch (InsecureRandRange(7 + (complexity >= 3) * 7 + (complexity >= 4) * 2)) {
            // Complexity >= 2
            case 0: return MakeNodeRef(NodeType::WRAP_C, MultiNode(complexity, Vector("K"_mst)));
            case 1: return MakeNodeRef(NodeType::WRAP_D, MultiNode(complexity - 1, Vector("V"_mst)));
            case 2: return MakeNodeRef(NodeType::WRAP_J, MultiNode(complexity - 1, Vector("B"_mst)));
            case 3: return MakeNodeRef(NodeType::WRAP_N, MultiNode(complexity - 1, Vector("B"_mst)));
            case 4: return MakeNodeRef(NodeType::OR_I, Cat(MultiNode(complexity - 1, Vector("B"_mst)), Vector(MakeNodeRef(NodeType::FALSE))));
            case 5: return MakeNodeRef(NodeType::OR_I, Cat(Vector(MakeNodeRef(NodeType::FALSE)), MultiNode(complexity - 1, Vector("B"_mst))));
            case 6: return MakeNodeRef(NodeType::AND_V, Cat(MultiNode(complexity - 1, Vector("V"_mst)), Vector(MakeNodeRef(NodeType::TRUE))));
            // Complexity >= 3
            case 7: return MakeNodeRef(NodeType::AND_V, MultiNode(complexity - 1, Vector("V"_mst, "B"_mst)));
            case 8: return MakeNodeRef(NodeType::ANDOR, Cat(MultiNode(complexity - 1, Vector("B"_mst, "B"_mst)), Vector(MakeNodeRef(NodeType::FALSE))));
            case 9: return MakeNodeRef(NodeType::AND_B, MultiNode(complexity - 1, Vector("B"_mst, "W"_mst)));
            case 10: return MakeNodeRef(NodeType::OR_B, MultiNode(complexity - 1, Vector("B"_mst, "W"_mst)));
            case 11: return MakeNodeRef(NodeType::OR_D, MultiNode(complexity - 1, Vector("B"_mst, "B"_mst)));
            case 12: return MakeNodeRef(NodeType::OR_I, MultiNode(complexity - 1, Vector("B"_mst, "B"_mst)));
            case 13: {
                if (complexity != 3) return {};
                int nkeys = 1 + (InsecureRandRange(15) * InsecureRandRange(25)) / 17;
                int sigs = 1 + InsecureRandRange(nkeys);
                std::vector<TestKey> keys;
                for (int i = 0; i < nkeys; ++i) keys.push_back(TestKey(InsecureRandRange(26)));
                return MakeNodeRef(NodeType::THRESH_M, std::move(keys), sigs);
            }
            // Complexity >= 4
            case 14: return MakeNodeRef(NodeType::ANDOR, MultiNode(complexity - 1, Vector("B"_mst, "B"_mst, "B"_mst)));
            case 15: {
                int args = 3 + InsecureRandRange(std::min(3, complexity - 3));
                int sats = 2 + InsecureRandRange(args - 2);
                return MakeNodeRef(NodeType::THRESH, MultiNode(complexity - 1, Cat(Vector("B"_mst), std::vector<miniscript::Type>(args - 1, "W"_mst))), sats);
            }
        }
    } else if (typ << "V"_mst) {
        switch (InsecureRandRange(1 + (complexity >= 3) * 3 + (complexity >= 4))) {
            // Complexity >= 1
            case 0: return MakeNodeRef(NodeType::WRAP_V, MultiNode(complexity, Vector("B"_mst)));
            // Complexity >= 3
            case 1: return MakeNodeRef(NodeType::AND_V, MultiNode(complexity - 1, Vector("V"_mst, "V"_mst)));
            case 2: return MakeNodeRef(NodeType::OR_C, MultiNode(complexity - 1, Vector("B"_mst, "V"_mst)));
            case 3: return MakeNodeRef(NodeType::OR_I, MultiNode(complexity - 1, Vector("V"_mst, "V"_mst)));
            // Complexity >= 4
            case 4: return MakeNodeRef(NodeType::ANDOR, MultiNode(complexity - 1, Vector("B"_mst, "V"_mst, "V"_mst)));
        }
    } else if (typ << "W"_mst) {
        auto sub = RandomNode("B"_mst, complexity);
        if (sub->GetType() << "o"_mst) {
            if (InsecureRandBool()) return MakeNodeRef(NodeType::WRAP_S, Vector(std::move(sub)));
        }
        return MakeNodeRef(NodeType::WRAP_A, Vector(std::move(sub)));
    } else if (typ << "K"_mst) {
        if (complexity == 1 || complexity == 2) {
            if (InsecureRandBool()) {
                return MakeNodeRef(NodeType::PK, Vector(TestKey(InsecureRandRange(26))));
            } else {
                return MakeNodeRef(NodeType::PK_H, Vector(TestKey(InsecureRandRange(26))));
            }
        }
        switch (InsecureRandRange(2 + (complexity >= 4))) {
            // Complexity >= 3
            case 0: return MakeNodeRef(NodeType::AND_V, MultiNode(complexity - 1, Vector("V"_mst, "K"_mst)));
            case 1: return MakeNodeRef(NodeType::OR_I, MultiNode(complexity - 1, Vector("K"_mst, "K"_mst)));
            // Complexity >= 4
            case 2: return MakeNodeRef(NodeType::ANDOR, MultiNode(complexity - 1, Vector("B"_mst, "K"_mst, "K"_mst)));
        }
    }
    assert(false);
    return {};
}

void FindChallenges(const NodeRef& ref, std::set<Challenge>& chal) {
    for (const auto& key : ref->keys) {
        chal.emplace(ChallengeType::PK, key.c);
    }
    for (const auto& sub : ref->subs) {
        FindChallenges(sub, chal);
    }
    if (ref->nodetype == miniscript::NodeType::OLDER) {
        chal.emplace(ChallengeType::OLDER, ref->k);
    } else if (ref->nodetype == miniscript::NodeType::AFTER) {
        chal.emplace(ChallengeType::AFTER, ref->k);
    } else if (ref->nodetype == miniscript::NodeType::SHA256) {
        int idx = FindHash(ref->data, ChallengeType::SHA256);
        if (idx != -1) chal.emplace(ChallengeType::SHA256, idx);
    } else if (ref->nodetype == miniscript::NodeType::RIPEMD160) {
        int idx = FindHash(ref->data, ChallengeType::RIPEMD160);
        if (idx != -1) chal.emplace(ChallengeType::RIPEMD160, idx);
    } else if (ref->nodetype == miniscript::NodeType::HASH256) {
        int idx = FindHash(ref->data, ChallengeType::HASH256);
        if (idx != -1) chal.emplace(ChallengeType::HASH256, idx);
    } else if (ref->nodetype == miniscript::NodeType::HASH160) {
        int idx = FindHash(ref->data, ChallengeType::HASH160);
        if (idx != -1) chal.emplace(ChallengeType::HASH160, idx);
    }
}

void Verify(const std::string& testcase, const NodeRef& node, const TestContext& ctx, std::vector<std::vector<unsigned char>> stack, const CScript& script, bool nonmal) {
    // Construct P2WSH scriptPubKey.
    CScript spk = GetScriptForDestination(WitnessV0ScriptHash(script));
    // Construct the P2WSH witness (script stack + script).
    CScriptWitness witness;
    witness.stack = std::move(stack);
    witness.stack.push_back(std::vector<unsigned char>(script.begin(), script.end()));
    // Use a test signature checker aware of which afters/olders we made valid.
    TestSignatureChecker checker(&ctx);
    ScriptError serror;
    if (nonmal) BOOST_CHECK(stack.size() <= node->GetStackSize());
    if (!VerifyScript(CScript(), spk, &witness, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serror)) {
        if (nonmal || serror != SCRIPT_ERR_OP_COUNT) { // Only the nonmalleable satisfier is guaranteed to stay below the ops limit
            fprintf(stderr, "\nFAILURE: %s\n", testcase.c_str());
            fprintf(stderr, "* Script: %s\n", ScriptToAsmStr(script).c_str());
            fprintf(stderr, "* Max ops: %i\n", node->GetOps());
            fprintf(stderr, "* Stack:");
            for (const auto& arg : stack) {
                fprintf(stderr, " %s", HexStr(arg).c_str());
            }
            fprintf(stderr, "* ERROR: %s\n", ScriptErrorString(serror));
            BOOST_CHECK(false);
        }
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(miniscript_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(random_miniscript_tests)
{
    for (int i = 0; i < 100000; ++i) {
        auto typ = InsecureRandRange(100) ? "B"_mst : "Bms"_mst; // require 1% strong, non-malleable
        auto node = RandomNode(typ, 1 + InsecureRandRange(90));
        auto str = node->ToString(CTX);
        auto script = node->ToScript(CTX);
        // Check consistency between script size estimation and real size
        BOOST_CHECK(node->ScriptSize() == script.size());
        // Check consistency of "x" property with the script (relying on the fact that in this test no keys or hashes end with a byte matching any of the opcodes below).
        BOOST_CHECK((node->GetType() << "x"_mst) != (script.back() == OP_CHECKSIG || script.back() == OP_CHECKMULTISIG || script.back() == OP_EQUAL));
        auto parsed = miniscript::FromString(str, CTX);
        // Check that we can parse the descriptor form back
        BOOST_CHECK(parsed);
        // Check that it matches the original
        if (parsed) {
            BOOST_CHECK(*parsed == *node);
        }
        auto decoded = miniscript::FromScript(script, CTX);
        // Check that we can decode the miniscript back from the script.
        BOOST_CHECK_MESSAGE(decoded, str);
        // Check that it matches the original (we can't use *decoded == *node because the miniscript representation may differ, but the script will always match)
        if (decoded) {
            BOOST_CHECK(decoded->ToScript(CTX) == script);
            BOOST_CHECK(decoded->GetType() == node->GetType());
        }

        std::set<Challenge> challenges;
        FindChallenges(node, challenges);
        std::vector<Challenge> challist(challenges.begin(), challenges.end());
        Shuffle(challist.begin(), challist.end(), g_insecure_rand_ctx);
        TestContext ctx;
        bool prev_mal_success = false, prev_nonmal_success = false;
        // Go over all challenges involved in this miniscript in random order; the first iteration does not add anything.
        for (int add = -1; add < (int)challist.size(); ++add) {
            if (add >= 0) {
                ctx.supported.insert(challist[add]);
            }
            std::vector<std::vector<unsigned char>> stack;
            bool mal_success = false;
            if (node->Satisfy(ctx, stack, false)) {
                Verify(str, node, ctx, stack, script, false);
                mal_success = true;
            }
            bool nonmal_success = false;
            if (node->Satisfy(ctx, stack, true)) {
                Verify(str, node, ctx, std::move(stack), std::move(script), true);
                nonmal_success = true;
            }
            // If a nonmalleable solution exists, a solution whatsoever must also exist.
            BOOST_CHECK(mal_success >= nonmal_success);
            // If a miniscript is nonmalleable/strong, and a solution exists, a non-malleable solution must also exist.
            if (node->GetType() << "ms"_mst) {
                BOOST_CHECK_EQUAL(nonmal_success, mal_success);
            }
            // Adding more satisfied conditions can never remove our ability to produce a satisfaction.
            BOOST_CHECK(mal_success >= prev_mal_success);
            prev_mal_success = mal_success;
            // For nonmalleable solutions this is only true if the added condition is PK; for other conditions, it may make an valid satisfaction become malleable
            if (add >= 0 && challist[add].first == ChallengeType::PK) {
                BOOST_CHECK(nonmal_success >= prev_nonmal_success);
                assert(nonmal_success >= prev_nonmal_success);
            }
            prev_nonmal_success = nonmal_success;
        }
        // If the miniscript was satisfiable at all, a satisfaction must be found after all conditions are added.
        BOOST_CHECK_EQUAL(prev_mal_success, Satisfiable(node));
    }
}

/*
+std::string RandomKey() {
+    const auto& key = g_testdata->pubkeys[InsecureRandRange(32)];
+    return HexStr(key.begin(), key.end());
+}
+
+std::string RandomMultisig() {
+    int n = 1 + InsecureRandRange(3);
+    int k = 1 + InsecureRandRange(n);
+    std::string ret = "thresh_m(" + std::to_string(k);
+    for (int i = 0; i < k; ++i) {
+        ret += ",";
+        ret += RandomKey();
+    }
+    ret += ")";
+    return ret;
+}
+
+std::string RandomHash() {
+    int i = InsecureRandRange(8);
+    switch (InsecureRandRange(4)) {
+    case 0: return "sha256(" + HexStr(g_testdata->sha256[i].begin(), g_testdata->sha256[i].end()) + ")";
+    case 1: return "hash256(" + HexStr(g_testdata->hash256[i].begin(), g_testdata->hash256[i].end()) + ")";
+    case 2: return "ripemd160(" + HexStr(g_testdata->ripemd160[i].begin(), g_testdata->ripemd160[i].end()) + ")";
+    case 3: return "hash160(" + HexStr(g_testdata->hash160[i].begin(), g_testdata->hash160[i].end()) + ")";
+    }
+    assert(false);
+    return "";
+}
+
+std::string RandomTime() {
+    static const std::vector<std::string> CHOICE{"older(1)", "older(16)", "older(144)", "older(2016)", "older(50000)", "older(4194305)", "older(4196667)", "older(4252898)","after(1)", "after(500000)", "after(499999999)", "after(1231488000)", "after(1567547623)"};
+    return CHOICE[InsecureRandRange(CHOICE.size())];
+}
+
+void Generate(void) {
+    printf("%s\n",strprintf("lltvln:%s\n", RandomTime()).c_str());
+    printf("%s\n",strprintf("uuj:and_v(v:%s,%s)", RandomMultisig(), RandomTime()).c_str());
+    printf("%s\n",strprintf("or_b(un:%s,al:%s)", RandomMultisig(), RandomTime()).c_str());
+    printf("%s\n",strprintf("j:and_v(vdv:%s,%s)", RandomTime(), RandomTime()).c_str());
+    printf("%s\n",strprintf("t:and_v(vu:%s,v:%s)", RandomHash(), RandomHash()).c_str());
+    printf("%s\n",strprintf("t:andor(%s,v:%s,v:%s)", RandomMultisig(), RandomTime(), RandomHash()).c_str());
+    printf("%s\n",strprintf("or_d(%s,or_b(%s,su:%s))", RandomMultisig(), RandomMultisig(), RandomTime()).c_str());
+    printf("%s\n",strprintf("or_d(%s,and_n(un:%s,%s))", RandomHash(), RandomTime(), RandomTime()).c_str());
+    printf("%s\n",strprintf("and_v(or_i(v:%s,v:%s),%s)", RandomMultisig(), RandomMultisig(), RandomHash()).c_str());
+    printf("%s\n",strprintf("j:and_b(%s,s:or_i(%s,%s))", RandomMultisig(), RandomTime(), RandomTime()).c_str());
+    printf("%s\n",strprintf("and_b(%s,s:or_d(%s,n:%s))", RandomTime(), RandomHash(), RandomTime()).c_str());
+    printf("%s\n",strprintf("j:and_v(v:%s,or_d(%s,%s))", RandomHash(), RandomHash(), RandomTime()).c_str());
+    printf("%s\n",strprintf("and_b(%s,a:and_b(%s,a:%s))", RandomHash(), RandomHash(), RandomTime()).c_str());
+    printf("%s\n",strprintf("thresh(2,%s,a:%s,ac:pk(%s))", RandomMultisig(), RandomMultisig(), RandomKey()).c_str());
+    printf("%s\n",strprintf("and_n(%s,t:or_i(v:%s,v:%s))", RandomHash(), RandomTime(), RandomTime()).c_str());
+    printf("%s\n",strprintf("or_d(d:and_v(v:%s,v:%s),%s)", RandomTime(), RandomTime(), RandomHash()).c_str());
+    printf("%s\n",strprintf("c:and_v(or_c(%s,v:%s),pk(%s))", RandomHash(), RandomMultisig(), RandomKey()).c_str());
+    printf("%s\n",strprintf("c:and_v(or_c(%s,v:%s),pk(%s))", RandomMultisig(), RandomHash(), RandomKey()).c_str());
+    printf("%s\n",strprintf("and_v(andor(%s,v:%s,v:%s),%s)", RandomHash(), RandomHash(), RandomTime(), RandomTime()).c_str());
+    printf("%s\n",strprintf("andor(%s,j:and_v(v:%s,%s),%s)", RandomHash(), RandomHash(), RandomTime(), RandomHash()).c_str());
+    printf("%s\n",strprintf("or_i(c:and_v(v:%s,pk(%s)),%s)", RandomTime(), RandomKey(), RandomHash()).c_str());
+    printf("%s\n",strprintf("thresh(2,c:pk_h(%s),s:%s,a:%s)", RandomKey(), RandomHash(), RandomHash()).c_str());
+    printf("%s\n",strprintf("and_n(%s,uc:and_v(v:%s,pk(%s)))", RandomHash(), RandomTime(), RandomKey()).c_str());
+    printf("%s\n",strprintf("and_n(c:pk(%s),and_b(l:%s,a:%s))", RandomKey(), RandomTime(), RandomTime()).c_str());
+    printf("%s\n",strprintf("c:or_i(and_v(v:%s,pk_h(%s)),pk_h(%s))", RandomTime(), RandomKey(), RandomKey()).c_str());
+    printf("%s\n",strprintf("or_d(c:pk_h(%s),andor(c:pk(%s),%s,%s))", RandomKey(), RandomKey(), RandomTime(), RandomTime()).c_str());
+    printf("%s\n",strprintf("c:andor(%s,pk_h(%s),and_v(v:%s,pk_h(%s)))", RandomHash(), RandomKey(), RandomHash(), RandomKey()).c_str());
+    printf("%s\n",strprintf("c:andor(u:%s,pk_h(%s),or_i(pk_h(%s),pk_h(%s)))", RandomHash(), RandomKey(), RandomKey(), RandomKey()).c_str());
+    printf("%s\n",strprintf("c:or_i(andor(c:pk_h(%s),pk_h(%s),pk_h(%s)),pk(%s))", RandomKey(), RandomKey(), RandomKey(), RandomKey()).c_str());
+}
*/

BOOST_AUTO_TEST_SUITE_END()
