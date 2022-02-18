// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <hash.h>
#include <key.h>
#include <script/miniscript.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/strencodings.h>


//! Some pre-computed data to simulate challenges.
struct TestData {
    typedef CPubKey Key;

    // Precomputed public keys, and a dummy signature for each of them.
    std::vector<Key> dummy_keys;
    std::map<CKeyID, Key> dummy_keys_map;
    std::map<Key, std::vector<unsigned char>> dummy_sigs;

    // Precomputed hashes of each kind.
    std::vector<std::vector<unsigned char>> sha256;
    std::vector<std::vector<unsigned char>> ripemd160;
    std::vector<std::vector<unsigned char>> hash256;
    std::vector<std::vector<unsigned char>> hash160;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> sha256_preimages;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> ripemd160_preimages;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> hash256_preimages;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> hash160_preimages;

    //! Set the precomputed data.
    void Init() {
        unsigned char keydata[32] = {1};
        for (size_t i = 0; i < 256; i++) {
            keydata[31] = i;
            CKey privkey;
            privkey.Set(keydata, keydata + 32, true);
            const Key pubkey = privkey.GetPubKey();

            dummy_keys.push_back(pubkey);
            dummy_keys_map.insert({pubkey.GetID(), pubkey});
            std::vector<unsigned char> sig;
            privkey.Sign(uint256S(""), sig);
            sig.push_back(1); // SIGHASH_ALL
            dummy_sigs.insert({pubkey, sig});

            std::vector<unsigned char> hash;
            hash.resize(32);
            CSHA256().Write(keydata, 32).Finalize(hash.data());
            sha256.push_back(hash);
            sha256_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            CHash256().Write(keydata).Finalize(hash);
            hash256.push_back(hash);
            hash256_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            hash.resize(20);
            CRIPEMD160().Write(keydata, 32).Finalize(hash.data());
            assert(hash.size() == 20);
            ripemd160.push_back(hash);
            ripemd160_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            CHash160().Write(keydata).Finalize(hash);
            hash160.push_back(hash);
            hash160_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
        }
    }
};

//! Context to parse a Miniscript node to and from Script or text representation.
struct ParserContext {
    typedef CPubKey Key;
    TestData *test_data;

    bool ToString(const Key& key, std::string& ret) const { ret = HexStr(key); return true; }

    const std::vector<unsigned char> ToPKBytes(const Key& key) const { return {key.begin(), key.end()}; }

    const std::vector<unsigned char> ToPKHBytes(const Key& key) const {
        const auto h = Hash160(key);
        return {h.begin(), h.end()};
    }

    template<typename I>
    bool FromString(I first, I last, Key& key) const {
        const auto bytes = ParseHex(std::string(first, last));
        key.Set(bytes.begin(), bytes.end());
        return key.IsValid();
    }

    template<typename I>
    bool FromPKBytes(I first, I last, CPubKey& key) const {
        key.Set(first, last);
        return key.IsValid();
    }

    template<typename I>
    bool FromPKHBytes(I first, I last, CPubKey& key) const {
        assert(last - first == 20);
        CKeyID keyid;
        std::copy(first, last, keyid.begin());
        const auto it = test_data->dummy_keys_map.find(keyid);
        if (it == test_data->dummy_keys_map.end()) return false;
        key = it->second;
        return true;
    }
};

//! Context to produce a satisfaction for a Miniscript node using the pre-computed data.
struct SatisfierContext: ParserContext {
    // Timelock challenges satisfaction. Make the value (deterministically) vary to explore different
    // paths.
    bool CheckAfter(uint32_t value) const { return value % 2; }
    bool CheckOlder(uint32_t value) const { return value % 2; }

    // Signature challenges fulfilled with a dummy signature, if it was one of our dummy keys.
    miniscript::Availability Sign(const CPubKey& key, std::vector<unsigned char>& sig) const {
        const auto it = test_data->dummy_sigs.find(key);
        if (it == test_data->dummy_sigs.end()) return miniscript::Availability::NO;
        sig = it->second;
        return miniscript::Availability::YES;
    }

    //! Lookup generalization for all the hash satisfactions below
    miniscript::Availability LookupHash(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage,
                                        const std::map<std::vector<unsigned char>, std::vector<unsigned char>>& map) const
    {
        const auto it = map.find(hash);
        if (it == map.end()) return miniscript::Availability::NO;
        preimage = it->second;
        return miniscript::Availability::YES;
    }
    miniscript::Availability SatSHA256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return LookupHash(hash, preimage, test_data->sha256_preimages);
    }
    miniscript::Availability SatRIPEMD160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return LookupHash(hash, preimage, test_data->ripemd160_preimages);
    }
    miniscript::Availability SatHASH256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return LookupHash(hash, preimage, test_data->hash256_preimages);
    }
    miniscript::Availability SatHASH160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return LookupHash(hash, preimage, test_data->hash160_preimages);
    }
};

//! Context to check a satisfaction against the pre-computed data.
struct CheckerContext: BaseSignatureChecker {
    TestData *test_data;

    // Signature checker methods. Checks the right dummy signature is used. Always assumes timelocks are
    // correct.
    bool CheckECDSASignature(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& vchPubKey,
                             const CScript& scriptCode, SigVersion sigversion) const override
    {
        const CPubKey key{vchPubKey};
        const auto it = test_data->dummy_sigs.find(key);
        if (it == test_data->dummy_sigs.end()) return false;
        return it->second == sig;
    }
    bool CheckLockTime(const CScriptNum& nLockTime) const override { return true; }
    bool CheckSequence(const CScriptNum& nSequence) const override { return true; }
};

// The various contexts
TestData TEST_DATA;
ParserContext PARSER_CTX;
SatisfierContext SATISFIER_CTX;
CheckerContext CHECKER_CTX;
// A dummy scriptsig to pass to VerifyScript (we always use Segwit v0).
const CScript DUMMY_SCRIPTSIG;

using Fragment = miniscript::Fragment;
using NodeRef = miniscript::NodeRef<CPubKey>;
using miniscript::operator"" _mst;

//! Construct a miniscript node as a shared_ptr.
template<typename... Args> NodeRef MakeNodeRef(Args&&... args) { return miniscript::MakeNodeRef<CPubKey>(std::forward<Args>(args)...); }

/** Information about a yet to be constructed Miniscript node. */
struct NodeInfo {
    //! The type of this node
    Fragment fragment;
    //! Number of subs of this node
    uint8_t n_subs;
    //! The timelock value for older() and after(), the threshold value for multi() and thresh()
    uint32_t k;
    //! Keys for this node, if it has some
    std::vector<CPubKey> keys;
    //! The hash value for this node, if it has one
    std::vector<unsigned char> hash;

    NodeInfo(Fragment frag): fragment(frag), n_subs(0), k(0) {}
    NodeInfo(Fragment frag, CPubKey key): fragment(frag), n_subs(0), k(0), keys({key}) {}
    NodeInfo(Fragment frag, uint32_t _k): fragment(frag), n_subs(0), k(_k) {}
    NodeInfo(Fragment frag, std::vector<unsigned char> h): fragment(frag), n_subs(0), k(0), hash(std::move(h)) {}
    NodeInfo(Fragment frag, uint8_t subs): fragment(frag), n_subs(subs), k(0) {}
    NodeInfo(Fragment frag, uint32_t _k, uint8_t subs): fragment(frag), n_subs(subs), k(_k) {}
    NodeInfo(Fragment frag, uint32_t _k, std::vector<CPubKey> _keys): fragment(frag), n_subs(0), k(_k), keys(std::move(_keys)) {}
};

/** Pick an index in a collection from a single byte in the fuzzer's output. */
template<typename T, typename A>
T ConsumeIndex(FuzzedDataProvider& provider, A& col) {
    const uint8_t i = provider.ConsumeIntegral<uint8_t>();
    return col[i];
}

CPubKey ConsumePubKey(FuzzedDataProvider& provider) {
    return ConsumeIndex<CPubKey>(provider, TEST_DATA.dummy_keys);
}

std::vector<unsigned char> ConsumeSha256(FuzzedDataProvider& provider) {
    return ConsumeIndex<std::vector<unsigned char>>(provider, TEST_DATA.sha256);
}

std::vector<unsigned char> ConsumeHash256(FuzzedDataProvider& provider) {
    return ConsumeIndex<std::vector<unsigned char>>(provider, TEST_DATA.hash256);
}

std::vector<unsigned char> ConsumeRipemd160(FuzzedDataProvider& provider) {
    return ConsumeIndex<std::vector<unsigned char>>(provider, TEST_DATA.ripemd160);
}

std::vector<unsigned char> ConsumeHash160(FuzzedDataProvider& provider) {
    return ConsumeIndex<std::vector<unsigned char>>(provider, TEST_DATA.hash160);
}

std::optional<uint32_t> ConsumeTimeLock(FuzzedDataProvider& provider) {
    const uint32_t k = provider.ConsumeIntegral<uint32_t>();
    if (k == 0 || k >= 0x80000000) return {};
    return k;
}

/**
 * Consume a Miniscript node from the fuzzer's output.
 *
 * This defines a very basic binary encoding for a Miniscript node:
 *  - The first byte sets the type of the fragment. 0, 1 and all non-leaf fragments buth thresh() are single
 *    byte.
 *  - For the other leaf fragments, the following bytes depend on their type.
 *    - For older() and after(), the next 4 bytes define the timelock value.
 *    - For pk_k(), pk_h(), and all hashes, the next byte defines the index of the value in the test data.
 *    - For multi(), the next 2 bytes define respectively the threshold and the number of keys. Then as many
 *      bytes as the number of keys define the index of each key in the test data.
 *    - For thresh(), the next byte defines the threshold value and the following one the number of subs.
 */
std::optional<NodeInfo> ConsumeNode(FuzzedDataProvider& provider) {
    switch (provider.ConsumeIntegral<uint8_t>()) {
        case 0: return NodeInfo(Fragment::JUST_0);
        case 1: return NodeInfo(Fragment::JUST_1);
        case 2: return NodeInfo(Fragment::PK_K, ConsumePubKey(provider));
        case 3: return NodeInfo(Fragment::PK_H, ConsumePubKey(provider));
        case 4: {
            const auto k = ConsumeTimeLock(provider);
            return k ? NodeInfo(Fragment::OLDER, *k) : std::optional<NodeInfo>{};
        }
        case 5: {
            const auto k = ConsumeTimeLock(provider);
            return k ? NodeInfo(Fragment::AFTER, *k) : std::optional<NodeInfo>{};
        }
        case 6: return NodeInfo(Fragment::SHA256, ConsumeSha256(provider));
        case 7: return NodeInfo(Fragment::HASH256, ConsumeHash256(provider));
        case 8: return NodeInfo(Fragment::RIPEMD160, ConsumeRipemd160(provider));
        case 9: return NodeInfo(Fragment::HASH160, ConsumeHash160(provider));
        case 10: {
            const auto k = provider.ConsumeIntegral<uint8_t>();
            const auto n_keys = provider.ConsumeIntegral<uint8_t>();
            if (n_keys > 20 || k == 0 || k > n_keys) return {};
            std::vector<CPubKey> keys{n_keys};
            for (auto& key: keys) key = ConsumePubKey(provider);
            return NodeInfo(Fragment::MULTI, k, keys);
        }
        case 11: return NodeInfo(Fragment::ANDOR, uint8_t{3});
        case 12: return NodeInfo(Fragment::AND_V, uint8_t{2});
        case 13: return NodeInfo(Fragment::AND_B, uint8_t{2});
        case 15: return NodeInfo(Fragment::OR_B, uint8_t{2});
        case 16: return NodeInfo(Fragment::OR_C, uint8_t{2});
        case 17: return NodeInfo(Fragment::OR_D, uint8_t{2});
        case 18: return NodeInfo(Fragment::OR_I, uint8_t{2});
        case 19: {
            auto k = provider.ConsumeIntegral<uint8_t>();
            auto n_subs = provider.ConsumeIntegral<uint8_t>();
            if (k == 0 || k > n_subs) return {};
            return NodeInfo(Fragment::THRESH, k, n_subs);
        }
        case 20: return NodeInfo(Fragment::WRAP_A, uint8_t{1});
        case 21: return NodeInfo(Fragment::WRAP_S, uint8_t{1});
        case 22: return NodeInfo(Fragment::WRAP_C, uint8_t{1});
        case 23: return NodeInfo(Fragment::WRAP_D, uint8_t{1});
        case 24: return NodeInfo(Fragment::WRAP_V, uint8_t{1});
        case 25: return NodeInfo(Fragment::WRAP_J, uint8_t{1});
        case 26: return NodeInfo(Fragment::WRAP_N, uint8_t{1});
        default: return {};
    }

    assert(false);
    return {};
}

/**
 * Generate a Miniscript node based on the fuzzer's input.
 */
NodeRef GenNode(FuzzedDataProvider& provider) {
    /** A stack of miniscript Nodes being built up. */
    std::vector<NodeRef> stack;
    /** The queue of instructions. */
    std::vector<std::optional<NodeInfo>> todo{{}};

    while (!todo.empty()) {
        // The expected type we have to construct.
        if (!todo.back()) {
            // Fragment/children have not been decided yet. Decide them.
            auto node_info = ConsumeNode(provider);
            uint8_t n_subs = node_info->n_subs;
            if (!node_info) return {};
            todo.back() = std::move(node_info);
            for (uint8_t i = 0; i < n_subs; i++) todo.push_back({});
        } else {
            // The back of todo has nodetype and number of children decided, and
            // those children have been constructed at the back of stack. Pop
            // that entry off todo, and use it to construct a new NodeRef on
            // stack.
            const NodeInfo& info = *todo.back();
            // Gather children from the back of stack.
            std::vector<NodeRef> sub;
            sub.reserve(info.n_subs);
            for (size_t i = 0; i < info.n_subs; ++i) {
                sub.push_back(std::move(*(stack.end() - info.n_subs + i)));
            }
            stack.erase(stack.end() - info.n_subs, stack.end());
            // Construct new NodeRef.
            NodeRef node;
            if (info.keys.empty()) {
                node = MakeNodeRef(info.fragment, std::move(sub), std::move(info.hash), info.k);
            } else {
                assert(sub.empty());
                assert(info.hash.empty());
                node = MakeNodeRef(info.fragment, std::move(info.keys), info.k);
            }
            // Verify acceptability.
            if (!node || !node->IsValid()) return {};
            // Move it to the stack.
            stack.push_back(std::move(node));
            todo.pop_back();
        }
    }
    assert(stack.size() == 1);
    return std::move(stack[0]);
}

//! Pre-compute the test data and point the various contexts to it.
void initialize_miniscript_random() {
    ECC_Start();
    TEST_DATA.Init();
    PARSER_CTX.test_data = &TEST_DATA;
    SATISFIER_CTX.test_data = &TEST_DATA;
    CHECKER_CTX.test_data = &TEST_DATA;
}

FUZZ_TARGET_INIT(miniscript_random, initialize_miniscript_random)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    // Generate a top-level node
    const auto node = GenNode(fuzzed_data_provider);
    if (!node || !node->IsValidTopLevel()) return;

    // Check roundtrip to Script, and consistency between script size estimation and real size
    const auto script = node->ToScript(PARSER_CTX);
    assert(node->ScriptSize() == script.size());
    auto decoded = miniscript::FromScript(script, PARSER_CTX);
    assert(decoded);
    // Note we can't use *decoded == *node because the miniscript representation may differ, so we check that:
    // - The script corresponding to that decoded form matchs exactly
    // - The type matches exactly
    assert(decoded->ToScript(PARSER_CTX) == script);
    assert(decoded->GetType() == node->GetType());

    // Check consistency of "x" property with the script (relying on the fact that no
    // top-level scripts end with a hash or key push, whose last byte could match these opcodes).
    bool ends_in_verify = !(node->GetType() << "x"_mst);
    assert(ends_in_verify == (script.back() == OP_CHECKSIG || script.back() == OP_CHECKMULTISIG || script.back() == OP_EQUAL));

    // Check that it roundtrips to text representation
    std::string str;
    assert(node->ToString(PARSER_CTX, str));
    auto parsed = miniscript::FromString(str, PARSER_CTX);
    assert(parsed);
    assert(*parsed == *node);

    // Check both malleable and non-malleable satisfaction. Note that we only assert the produced witness
    // is valid if the Miniscript was sane, as otherwise it could overflow the limits.
    CScriptWitness witness;
    const CScript script_pubkey = CScript() << OP_0 << WitnessV0ScriptHash(script);
    const bool mal_success = node->Satisfy(SATISFIER_CTX, witness.stack, false) == miniscript::Availability::YES;
    if (mal_success && node->IsSaneTopLevel()) {
        witness.stack.push_back(std::vector<unsigned char>(script.begin(), script.end()));
        assert(VerifyScript(DUMMY_SCRIPTSIG, script_pubkey, &witness, STANDARD_SCRIPT_VERIFY_FLAGS, CHECKER_CTX));
    }
    witness.stack.clear();
    const bool nonmal_success = node->Satisfy(SATISFIER_CTX, witness.stack, true) == miniscript::Availability::YES;
    if (nonmal_success && node->IsSaneTopLevel()) {
        witness.stack.push_back(std::vector<unsigned char>(script.begin(), script.end()));
        assert(VerifyScript(DUMMY_SCRIPTSIG, script_pubkey, &witness, STANDARD_SCRIPT_VERIFY_FLAGS, CHECKER_CTX));
    }
    // If a nonmalleable solution exists, a solution whatsoever must also exist.
    assert(mal_success >= nonmal_success);
    // If a miniscript is nonmalleable and needs a signature, and a solution exists, a non-malleable solution must also exist.
    if (node->IsNonMalleable() && node->NeedsSignature()) assert(nonmal_success == mal_success);
}
