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
// We generate the pseudorandom nodes recursively, this puts a bound.
static constexpr size_t MAX_NESTED_DEPTH = 402;

using NodeType = miniscript::NodeType;
using NodeRef = miniscript::NodeRef<CPubKey>;
using miniscript::operator"" _mst;

//! Construct a miniscript node as a shared_ptr.
template<typename... Args> NodeRef MakeNodeRef(Args&&... args) { return miniscript::MakeNodeRef<CPubKey>(std::forward<Args>(args)...); }

/**
 * Generate a Miniscript node based on the fuzzer's input.
 * Note this does not attempt to produce a well-typed (let alone safe) Miniscript node.
 */
NodeRef GenNode(FuzzedDataProvider& provider, const miniscript::Type typ, const size_t recursion_depth);

/**
 * Generate a pseudorandom node. If invalid, return NULL.
 * Used to cut-through as a node with invalid subs will never be valid.
 */
NodeRef GenValidNode(FuzzedDataProvider& provider, const miniscript::Type typ, const size_t recursion_depth)
{
    const NodeRef node = GenNode(provider, typ, recursion_depth);
    if (!node || !node->IsValid() || !(node->GetType() << typ)) return {};
    return node;
}

//! Generate a vector of miniscript nodes of the given types.
std::vector<NodeRef> MultiNode(FuzzedDataProvider& provider, const std::initializer_list<miniscript::Type> types,
                               const size_t recursion_depth)
{
    std::vector<NodeRef> subs;
    for (const auto type : types) {
        NodeRef sub = GenValidNode(provider, type, recursion_depth);
        if (!sub) return {};
        subs.push_back(std::move(sub));
    }
    return subs;
}

//! Generate a node with pseudorandom subs of the given types.
NodeRef MultiSubs(FuzzedDataProvider& provider, const NodeType node_type, const std::initializer_list<miniscript::Type> subtypes,
                  const size_t recursion_depth)
{
    auto subs = MultiNode(provider, subtypes, recursion_depth);
    if (subs.empty()) return {};
    return MakeNodeRef(node_type, std::move(subs));
}

NodeRef GenNode(FuzzedDataProvider& provider, const miniscript::Type typ, const size_t recursion_depth) {
    if (recursion_depth >= MAX_NESTED_DEPTH) return {};

    if (typ << "B"_mst) {
        switch (provider.ConsumeIntegralInRange<size_t>(0, 19)) {
            case 0: return MakeNodeRef(provider.ConsumeBool() ? NodeType::JUST_0 : NodeType::JUST_1);
            case 1: {
                const uint32_t k{provider.ConsumeIntegralInRange<uint32_t>(1, CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG - 1)};
                return MakeNodeRef(provider.ConsumeBool() ? NodeType::OLDER : NodeType::AFTER, k);
            }
            case 2: {
                const size_t hashtype = provider.ConsumeIntegralInRange<size_t>(0, 3);
                const size_t index = provider.ConsumeIntegralInRange<size_t>(0, 255);
                switch (hashtype) {
                    case 0: return MakeNodeRef(NodeType::SHA256, TEST_DATA.sha256[index]);
                    case 1: return MakeNodeRef(NodeType::RIPEMD160, TEST_DATA.ripemd160[index]);
                    case 2: return MakeNodeRef(NodeType::HASH256, TEST_DATA.hash256[index]);
                    case 3: return MakeNodeRef(NodeType::HASH160, TEST_DATA.hash160[index]);
                }
            }
            case 3: {
                if (NodeRef sub = GenValidNode(provider, "K"_mst, recursion_depth + 1)) {
                    return MakeNodeRef(NodeType::WRAP_C, Vector(std::move(sub)));
                }
                return {};
            }
            case 4: {
                if (NodeRef sub = GenValidNode(provider, "K"_mst, recursion_depth + 1)) {
                    return MakeNodeRef(NodeType::WRAP_C, Vector(std::move(sub)));
                }
                return {};
            }
            case 5: {
                if (NodeRef sub = GenValidNode(provider, "V"_mst, recursion_depth + 1)) {
                    return MakeNodeRef(NodeType::WRAP_D, Vector(std::move(sub)));
                }
                return {};
            }
            case 6: {
                if (NodeRef sub = GenValidNode(provider, "B"_mst, recursion_depth + 1)) {
                    return MakeNodeRef(NodeType::WRAP_J, Vector(std::move(sub)));
                }
                return {};
            }
            case 7: {
                if (NodeRef sub = GenValidNode(provider, "B"_mst, recursion_depth + 1)) {
                    return MakeNodeRef(NodeType::WRAP_N, Vector(std::move(sub)));
                }
                return {};
            }
            case 8: {
                if (NodeRef sub = GenValidNode(provider, "B"_mst, recursion_depth + 1)) {
                    return MakeNodeRef(NodeType::OR_I, Vector(std::move(sub), MakeNodeRef(NodeType::JUST_0)));
                }
                return {};
            }
            case 9: {
                if (NodeRef sub = GenValidNode(provider, "B"_mst, recursion_depth + 1)) {
                    return MakeNodeRef(NodeType::OR_I, Vector(MakeNodeRef(NodeType::JUST_0), std::move(sub)));
                }
                return {};
            }
            case 10: {
                if (NodeRef sub = GenValidNode(provider, "V"_mst, recursion_depth + 1)) {
                    return MakeNodeRef(NodeType::AND_V, Vector(std::move(sub), MakeNodeRef(NodeType::JUST_1)));
                }
                return {};
            }
            case 11: {
                if (NodeRef sub = GenValidNode(provider, "V"_mst, recursion_depth + 1)) {
                    return MakeNodeRef(NodeType::AND_V, Vector(std::move(sub), MakeNodeRef(NodeType::JUST_1)));
                }
                return {};
            }
            case 12: {
                auto subs = MultiNode(provider, {"B"_mst, "B"_mst}, recursion_depth + 1);
                if (subs.empty()) return {};
                subs.push_back(MakeNodeRef(NodeType::JUST_0));
                return MakeNodeRef(NodeType::ANDOR, std::move(subs));
            }
            case 13: return MultiSubs(provider, NodeType::AND_B, {"B"_mst, "W"_mst}, recursion_depth + 1);
            case 14: return MultiSubs(provider, NodeType::OR_B, {"B"_mst, "W"_mst}, recursion_depth + 1);
            case 15: return MultiSubs(provider, NodeType::OR_D, {"B"_mst, "B"_mst}, recursion_depth + 1);
            case 16: return MultiSubs(provider, NodeType::OR_I, {"B"_mst, "B"_mst}, recursion_depth + 1);
            case 17: {
                const size_t n_keys = provider.ConsumeIntegralInRange(1, 20);
                const size_t n_sigs = provider.ConsumeIntegralInRange<size_t>(1, n_keys);
                std::vector<CPubKey> keys;
                for (size_t i = 0; i < n_keys; ++i) keys.push_back(TEST_DATA.dummy_keys[provider.ConsumeIntegralInRange(0, 255)]);
                return MakeNodeRef(NodeType::MULTI, std::move(keys), n_sigs);
            }
            case 18: return MultiSubs(provider, NodeType::ANDOR, {"B"_mst, "B"_mst, "B"_mst}, recursion_depth + 1);
            case 19: {
                const size_t n_subs = 3 + provider.ConsumeIntegralInRange(0, 90);
                const uint32_t k = 2 + provider.ConsumeIntegralInRange<uint32_t>(0, n_subs - 3);
                const auto types = Cat(Vector("B"_mst), std::vector<miniscript::Type>(n_subs - 1, "W"_mst));
                std::vector<NodeRef> subs;
                for (const auto type : types) {
                    NodeRef sub = GenValidNode(provider, type, recursion_depth);
                    if (!sub) return {};
                    subs.push_back(std::move(sub));
                }
                if (subs.empty()) return {};
                return MakeNodeRef(NodeType::THRESH, subs, k);
            }
        }
    } else if (typ << "V"_mst) {
        switch (provider.ConsumeIntegralInRange(0, 4)) {
            case 0: {
                if (NodeRef sub = GenValidNode(provider, "B"_mst, recursion_depth + 1)) {
                    return MakeNodeRef(NodeType::WRAP_V, Vector(std::move(sub)));
                }
                return {};
            }
            case 1: return MultiSubs(provider, NodeType::AND_V, {"V"_mst, "V"_mst}, recursion_depth + 1);
            case 2: return MultiSubs(provider, NodeType::OR_C, {"B"_mst, "V"_mst}, recursion_depth + 1);
            case 3: return MultiSubs(provider, NodeType::OR_I, {"V"_mst, "V"_mst}, recursion_depth + 1);
            case 4: return MultiSubs(provider, NodeType::ANDOR, {"B"_mst, "V"_mst, "V"_mst}, recursion_depth + 1);
        }
    } else if (typ << "W"_mst) {
        // Generate a "W" node by wrapping a "B" node.
        auto sub = GenValidNode(provider, "B"_mst, recursion_depth + 1);
        if (!sub) return {};
        if (sub->GetType() << "o"_mst && provider.ConsumeBool()) {
            return MakeNodeRef(NodeType::WRAP_S, Vector(std::move(sub)));
        }
        return MakeNodeRef(NodeType::WRAP_A, Vector(std::move(sub)));
    } else if (typ << "K"_mst) {
        // Generate a "K" node.
        switch (provider.ConsumeIntegralInRange(0, 4)) {
            case 0: return MakeNodeRef(NodeType::PK_K, Vector(TEST_DATA.dummy_keys[provider.ConsumeIntegralInRange(0, 255)]));
            case 1: return MakeNodeRef(NodeType::PK_H, Vector(TEST_DATA.dummy_keys[provider.ConsumeIntegralInRange(0, 255)]));
            case 2: return MultiSubs(provider, NodeType::AND_V, {"V"_mst, "K"_mst}, recursion_depth + 1);
            case 3: return MultiSubs(provider, NodeType::OR_I, {"K"_mst, "K"_mst}, recursion_depth + 1);
            case 4: return MultiSubs(provider, NodeType::ANDOR, {"B"_mst, "K"_mst, "K"_mst}, recursion_depth + 1);
        }
    }
    assert(false);
    return {};
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
    const auto node = GenNode(fuzzed_data_provider, "B"_mst, 0);
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
