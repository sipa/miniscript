// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_SCRIPT_MINISCRIPT_H_
#define _BITCOIN_SCRIPT_MINISCRIPT_H_ 1

#include <algorithm>
#include <numeric>
#include <memory>
#include <string>
#include <vector>

#include <stdlib.h>
#include <assert.h>

#include <script/script.h>
#include <span.h>
#include <util/spanparsing.h>
#include <util/strencodings.h>
#include <util/vector.h>

namespace miniscript {

/** This type encapsulates the miniscript type system properties.
 *
 * Every miniscript expression is one of 4 basic types, and additionally has
 * a number of boolean type properties.
 *
 * The basic types are:
 * - "B" Base:
 *   - Takes its inputs from the top of the stack.
 *   - When satisfied, pushes a nonzero value of up to 4 bytes onto the stack.
 *   - When dissatisfied, pushes a 0 onto the stack.
 *   - This is used for most expressions, and required for the top level one.
 *   - For example: older(n) = <n> OP_CHECKSEQUENCEVERIFY.
 * - "V" Verify:
 *   - Takes its inputs from the top of the stack.
 *   - When satisfactied, pushes nothing.
 *   - Cannot be dissatisfied.
 *   - This is obtained by adding an OP_VERIFY to a B, modifying the last opcode
 *     of a B to its -VERIFY version (only for OP_CHECKSIG, OP_CHECKSIGVERIFY
 *     and OP_EQUAL), or using IFs where both branches are also Vs.
 *   - For example vc:pk(key) = <key> OP_CHECKSIGVERIFY
 * - "K" Key:
 *   - Takes its inputs from the top of the stack.
 *   - Becomes a B when followed by OP_CHECKSIG.
 *   - Always pushes a public key onto the stack, for which a signature is to be
 *     provided to satisfy the expression.
 *   - For example pk_h(key) = OP_DUP OP_HASH160 <Hash160(key)> OP_EQUALVERIFY
 * - "W" Wrapped:
 *   - Takes its input from one below the top of the stack.
 *   - When satisfied, pushes a nonzero value (like B) on top of the stack, or one below.
 *   - When dissatisfied, pushes 0 op top of the stack or one below.
 *   - Is always "OP_SWAP [B]" or "OP_TOALTSTACK [B] OP_FROMALTSTACK".
 *   - For example sc:pk(key) = OP_SWAP <key> OP_CHECKSIG
 *
 * There a type properties that help reasoning about correctness:
 * - "z" Zero-arg:
 *   - Is known to always consume exactly 0 stack elements.
 *   - For example after(n) = <n> OP_CHECKLOCKTIMEVERIFY
 * - "o" One-arg:
 *   - Is known to always consume exactly 1 stack element.
 *   - Conflicts with property 'z'
 *   - For example sha256(hash) = OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL
 * - "n" Nonzero:
 *   - For every way this expression can be satisfied, a satisfaction exists that never needs
 *     a zero top stack element.
 *   - Conflicts with property 'z' and with type 'W'.
 * - "d" Dissatisfiable:
 *   - There is an easy way to construct a dissatisfaction for this expression.
 *   - Conflicts with type 'V'.
 * - "u" Unit:
 *   - In case of satisfaction, an exact 1 is put on the stack (rather than just nonzero).
 *   - Conflicts with type 'V'.
 *
 * Additional type properties help reasoning about nonmalleability:
 * - "e" Expression:
 *   - This implies property 'd', but the dissatisfaction is nonmalleable.
 *   - This generally requires 'e' for all subexpressions which are invoked for that
 *     dissatifsaction, and property 'f' for the unexecuted subexpressions in that case.
 *   - Conflicts with type 'V'.
 * - "f" Forced:
 *   - Dissatisfactions (if any) for this expression always involve at least one signature.
 *   - Is always true for type 'V'.
 * - "s" Safe:
 *   - Satisfactions for this expression always involve at least one signature.
 * - "m" Nonmalleable:
 *   - For every way this expression can be satisfied (which may be none),
 *     a nonmalleable satisfaction exists.
 *   - This generally requires 'm' for all subexpressions, and 'e' for all subexpressions
 *     which are dissatisfied when satisfying the parent.
 *
 * One final type property is an implementation detail:
 * - "x" Expensive verify:
 *   - Expressions with this property have a script whose last opcode is not EQUAL, CHECKSIG, or CHECKMULTISIG.
 *   - Not having this property means that it can be converted to a V at no cost (by switching to the
 *     -VERIFY version of the last opcode).
 *
 * For each of these properties the subset rule holds: an expression with properties X, Y, and Z, is also
 * valid in places where an X, a Y, a Z, an XY, ... is expected.
*/
class Type {
    //! Internal bitmap of properties (see ""_mst operator for details).
    uint16_t m_flags;

    //! Internal constructed used by the ""_mst operator.
    explicit constexpr Type(uint16_t flags) : m_flags(flags) {}

public:
    //! The only way to publicly construct a Type is using this literal operator.
    friend constexpr Type operator"" _mst(const char* c, size_t l);

    //! Compute the type with the union of properties.
    constexpr Type operator|(Type x) const { return Type(m_flags | x.m_flags); }

    //! Compute the type with the intersection of properties.
    constexpr Type operator&(Type x) const { return Type(m_flags & x.m_flags); }

    //! Check whether the left hand's properties are superset of the right's (= left is a subtype of right).
    constexpr bool operator<<(Type x) const { return (x.m_flags & ~m_flags) == 0; }

    //! Comparison operator to enable use in sets/maps (total ordering incompatible with <<).
    constexpr bool operator<(Type x) const { return m_flags < x.m_flags; }

    //! Equality operator.
    constexpr bool operator==(Type x) const { return m_flags == x.m_flags; }

    //! The empty type if x is false, itself otherwise.
    constexpr Type If(bool x) const { return Type(x ? m_flags : 0); }

    constexpr uint16_t Int() const { return m_flags; }
};

//! Literal operator to construct Type objects.
inline constexpr Type operator""_mst(const char* c, size_t l) {
    return l == 0 ? Type(0) : operator"" _mst(c + 1, l - 1) | Type(
        *c == 'B' ? 1 << 0 : // Base type
        *c == 'V' ? 1 << 1 : // Verify type
        *c == 'K' ? 1 << 2 : // Key type
        *c == 'W' ? 1 << 3 : // Wrapped type
        *c == 'z' ? 1 << 4 : // Zero-arg property
        *c == 'o' ? 1 << 5 : // One-arg property
        *c == 'n' ? 1 << 6 : // Nonzero arg property
        *c == 'd' ? 1 << 7 : // Dissatisfiable property
        *c == 'u' ? 1 << 8 : // Unit property
        *c == 'e' ? 1 << 9 : // Expression property
        *c == 'f' ? 1 << 10 : // Forced property
        *c == 's' ? 1 << 11 : // Safe property
        *c == 'm' ? 1 << 12 : // Nonmalleable property
        *c == 'x' ? 1 << 13 : // Expensive verify
        (throw std::logic_error("Unknown character in _mst literal"), 0)
    );
}

template<typename Key> struct Node;
template<typename Key> using NodeRef = std::shared_ptr<const Node<Key>>;

//! Construct a miniscript node as a shared_ptr.
template<typename Key, typename... Args>
NodeRef<Key> MakeNodeRef(Args&&... args) { return std::make_shared<const Node<Key>>(std::forward<Args>(args)...); }

//! The different node types in miniscript.
enum class NodeType {
    FALSE,     //!< OP_0
    TRUE,      //!< OP_1
    PK,        //!< [key]
    PK_H,      //!< OP_DUP OP_HASH160 [keyhash] OP_EQUALVERFIFY
    OLDER,     //!< [n] OP_CHECKSEQUENCEVERIFY
    AFTER,     //!< [n] OP_CHECKLOCKTIMEVERIFY
    SHA256,    //!< OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 [hash] OP_EQUAL
    HASH256,   //!< OP_SIZE 32 OP_EQUALVERIFY OP_HASH256 [hash] OP_EQUAL
    RIPEMD160, //!< OP_SIZE 32 OP_EQUALVERIFY OP_RIPEMD160 [hash] OP_EQUAL
    HASH160,   //!< OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 [hash] OP_EQUAL
    WRAP_A,    //!< OP_TOALTSTACK [X] OP_FROMALTSTACK
    WRAP_S,    //!< OP_SWAP [X]
    WRAP_C,    //!< [X] OP_CHECKSIG
    WRAP_D,    //!< OP_DUP OP_IF [X] OP_ENDIF
    WRAP_V,    //!< [X] OP_VERIFY (or -VERIFY version of last opcode in X)
    WRAP_J,    //!< OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
    WRAP_N,    //!< [X] OP_0NOTEQUAL
    AND_V,     //!< [X] [Y]
    AND_B,     //!< [X] [Y] OP_BOOLAND
    OR_B,      //!< [X] [Y] OP_BOOLOR
    OR_C,      //!< [X] OP_NOTIF [Y] OP_ENDIF
    OR_D,      //!< [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
    OR_I,      //!< IF [X] OP_ELSE [Y] OP_ENDIF
    ANDOR,     //!< [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
    THRESH,    //!< [X1] ([Xn] OP_ADD)* [k] OP_EQUAL
    THRESH_M,  //!< [k] [key_n]* [n] OP_CHECKMULTISIG
    // AND_N(X,Y) is represented as ANDOR(X,Y,0)
    // WRAP_T(X) is represented as AND_V(X,1)
    // WRAP_L(X) is represented as OR_I(0,X)
    // WRAP_U(X) is represented as OR_I(X,0)
};

namespace internal {

//! Helper function for Node::CalcType.
Type ComputeType(NodeType nodetype, Type x, Type y, Type z, const std::vector<Type>& sub_types, uint32_t k, size_t data_size, size_t n_subs, size_t n_keys);

//! Helper function for Node::CalcScriptLen.
size_t ComputeScriptLen(NodeType nodetype, Type sub0typ, size_t subsize, uint32_t k, size_t n_subs, size_t n_keys);

//! A helper sanitizer/checker for the output of CalcType.
Type SanitizeType(Type x);

//! An object representing a sequence of witness stack elements.
struct InputStack {
    //! Whether this stack is valid for its intended purpose (satisfaction or dissatisfaction of a Node).
    bool valid = false;
    //! Whether this stack contains a digital signature.
    bool has_sig = false;
    //! Whether this stack is malleable (can be turned into an equally valid other stack by a third party).
    bool malleable = false;
    //! Whether this stack is non-canonical (using a construction known to be unnecessary for satisfaction).
    bool non_canon = false;
    //! Serialized witness size.
    size_t size = 0;
    //! Data elements.
    std::vector<std::vector<unsigned char>> stack;
    //! Construct an empty stack (valid or invalid).
    explicit InputStack(bool val) : valid(val), size(0) {}
    //! Construct a valid single-element stack (with an element up to 75 bytes).
    InputStack(std::vector<unsigned char> in) : valid(true), size(in.size() + 1), stack(Vector(std::move(in))) {}
    //! Mark this input stack as having a signature.
    InputStack& WithSig();
    //! Mark this input stack as non-canonical (known to not be necessary in non-malleable satisfactions).
    InputStack& NonCanon();
    //! Mark this input stack as malleable.
    InputStack& Malleable(bool x = true);
    //! Compare two InputStack objects.
    friend bool operator<(const InputStack& a, const InputStack& b);
    //! Concatenate two input stacks.
    friend InputStack operator+(InputStack a, InputStack b);
    //! Choose between two potential input stacks.
    friend InputStack Choose(InputStack a, InputStack b, bool nonmalleable);
};

//! A pair of a satisfaction and a dissatisfaction InputStack.
struct InputResult {
    InputStack nsat, sat;
    InputResult(InputStack in_nsat, InputStack in_sat) : nsat(std::move(in_nsat)), sat(std::move(in_sat)) {}
};

//! Class whose objects represent the maximum of a list of integers.
template<typename I>
struct MaxInt {
    const bool valid;
    const I value;

    MaxInt() : valid(false), value(0) {}
    MaxInt(I val) : valid(true), value(val) {}

    friend MaxInt<I> operator+(const MaxInt<I>& a, const MaxInt<I>& b) {
        if (!a.valid || !b.valid) return {};
        return a.value + b.value;
    }

    friend MaxInt<I> Choose(const MaxInt<I>& a, const MaxInt<I>& b) {
        if (!a.valid) return b;
        if (!b.valid) return a;
        return std::max(a.value, b.value);
    }
};

struct Ops {
    //! Non-push opcodes.
    uint32_t stat;
    //! Number of keys in possibly executed OP_CHECKMULTISIG(VERIFY)s to satisfy.
    MaxInt<uint32_t> sat;
    //! Number of keys in possibly executed OP_CHECKMULTISIG(VERIFY)s to dissatisfy.
    MaxInt<uint32_t> dsat;

    Ops(uint32_t in_stat, MaxInt<uint32_t> in_sat, MaxInt<uint32_t> in_dsat) : stat(in_stat), sat(in_sat), dsat(in_dsat) {};
};

struct StackSize {
    //! Maximum stack size to satisfy;
    MaxInt<uint32_t> sat;
    //! Maximum stack size to dissatisfy;
    MaxInt<uint32_t> dsat;

    StackSize(MaxInt<uint32_t> in_sat, MaxInt<uint32_t> in_dsat) : sat(in_sat), dsat(in_dsat) {};
};

} // namespace internal

//! A node in a miniscript expression.
template<typename Key>
struct Node {
    //! What node type this node is.
    const NodeType nodetype;
    //! The k parameter (time for OLDER/AFTER, threshold for THRESH(_M))
    const uint32_t k = 0;
    //! The keys used by this expression (only for PK/PK_H/THRESH_M)
    const std::vector<Key> keys;
    //! The data bytes in this expression (only for HASH160/HASH256/SHA256/RIPEMD10).
    const std::vector<unsigned char> data;
    //! Subexpressions (for WRAP_*/AND_*/OR_*/ANDOR/THRESH)
    const std::vector<NodeRef<Key>> subs;

private:
    //! Cached ops counts.
    const internal::Ops ops;
    //! Cached stack size bounds.
    const internal::StackSize ss;
    //! Cached expression type (computed by CalcType and fed through SanitizeType).
    const Type typ;
    //! Cached script length (computed by CalcScriptLen).
    const size_t scriptlen;
public:
    const std::set<uint32_t> types;

private:
    std::set<uint32_t> CalcTypes() const {
//        std::set<uint16_t> ret{(typ & "BKVWzonudfemsx"_mst).Int()};
        std::set<uint32_t> ret;
        uint32_t nt = (uint32_t)nodetype;
        if (nodetype == NodeType::AND_V && subs[1]->nodetype == NodeType::TRUE) {
            nt = (uint32_t)NodeType::THRESH_M + 1;
        } else if (nodetype == NodeType::ANDOR && subs[2]->nodetype == NodeType::FALSE) {
            nt = (uint32_t)NodeType::THRESH_M + 2;
        } else if (nodetype == NodeType::OR_I && subs[0]->nodetype == NodeType::FALSE) {
            nt = (uint32_t)NodeType::THRESH_M + 3;
        } else if (nodetype == NodeType::OR_I && subs[1]->nodetype == NodeType::FALSE) {
            nt = (uint32_t)NodeType::THRESH_M + 4;
        }

        ret.insert(nt * 64 + (typ & "BKVW"_mst).Int() * 2);
        ret.insert((typ & "BKVWzondu"_mst).Int() + 1);
        for (const auto& sub : subs) {
//            ret.insert((uint32_t)nodetype * 32 + (uint32_t)sub->nodetype);
            ret.insert(sub->types.begin(), sub->types.end());
        }
        return ret;
    }

    //! Compute the length of the script for this miniscript (including children).
    size_t CalcScriptLen() const {
        size_t subsize = 0;
        for (const auto& sub : subs) {
            subsize += sub->ScriptSize();
        }
        Type sub0type = subs.size() > 0 ? subs[0]->GetType() : ""_mst;
        return internal::ComputeScriptLen(nodetype, sub0type, subsize, k, subs.size(), keys.size());
    }

    //! Compute the type for this miniscript.
    Type CalcType() const {
        using namespace internal;

        // THRESH has a variable number of subexpression
        std::vector<Type> sub_types;
        if (nodetype == NodeType::THRESH) {
            for (const auto& sub : subs) sub_types.push_back(sub->GetType());
        }
        // All other nodes than THRESH can be computed just from the types of the 0-3 subexpexpressions.
        Type x = subs.size() > 0 ? subs[0]->GetType() : ""_mst;
        Type y = subs.size() > 1 ? subs[1]->GetType() : ""_mst;
        Type z = subs.size() > 2 ? subs[2]->GetType() : ""_mst;

        return SanitizeType(ComputeType(nodetype, x, y, z, sub_types, k, data.size(), subs.size(), keys.size()));
    }

    //! Internal code for ToScript.
    template<typename Ctx>
    CScript MakeScript(const Ctx& ctx, bool verify = false) const {
        std::vector<unsigned char> bytes;
        switch (nodetype) {
            case NodeType::PK: return CScript() << ctx.ToPKBytes(keys[0]);
            case NodeType::PK_H: return CScript() << OP_DUP << OP_HASH160 << ctx.ToPKHBytes(keys[0]) << OP_EQUALVERIFY;
            case NodeType::OLDER: return CScript() << k << OP_CHECKSEQUENCEVERIFY;
            case NodeType::AFTER: return CScript() << k << OP_CHECKLOCKTIMEVERIFY;
            case NodeType::SHA256: return CScript() << OP_SIZE << 32 << OP_EQUALVERIFY << OP_SHA256 << data << (verify ? OP_EQUALVERIFY : OP_EQUAL);
            case NodeType::RIPEMD160: return CScript() << OP_SIZE << 32 << OP_EQUALVERIFY << OP_RIPEMD160 << data << (verify ? OP_EQUALVERIFY : OP_EQUAL);
            case NodeType::HASH256: return CScript() << OP_SIZE << 32 << OP_EQUALVERIFY << OP_HASH256 << data << (verify ? OP_EQUALVERIFY : OP_EQUAL);
            case NodeType::HASH160: return CScript() << OP_SIZE << 32 << OP_EQUALVERIFY << OP_HASH160 << data << (verify ? OP_EQUALVERIFY : OP_EQUAL);
            case NodeType::WRAP_A: return (CScript() << OP_TOALTSTACK) + subs[0]->MakeScript(ctx) + (CScript() << OP_FROMALTSTACK);
            case NodeType::WRAP_S: return (CScript() << OP_SWAP) + subs[0]->MakeScript(ctx, verify);
            case NodeType::WRAP_C: return subs[0]->MakeScript(ctx) + CScript() << (verify ? OP_CHECKSIGVERIFY : OP_CHECKSIG);
            case NodeType::WRAP_D: return (CScript() << OP_DUP << OP_IF) + subs[0]->MakeScript(ctx) + (CScript() << OP_ENDIF);
            case NodeType::WRAP_V: return subs[0]->MakeScript(ctx, true) + (subs[0]->GetType() << "x"_mst ? (CScript() << OP_VERIFY) : CScript());
            case NodeType::WRAP_J: return (CScript() << OP_SIZE << OP_0NOTEQUAL << OP_IF) + subs[0]->MakeScript(ctx) + (CScript() << OP_ENDIF);
            case NodeType::WRAP_N: return subs[0]->MakeScript(ctx) + CScript() << OP_0NOTEQUAL;
            case NodeType::TRUE: return CScript() << OP_1;
            case NodeType::FALSE: return CScript() << OP_0;
            case NodeType::AND_V: return subs[0]->MakeScript(ctx) + subs[1]->MakeScript(ctx, verify);
            case NodeType::AND_B: return subs[0]->MakeScript(ctx) + subs[1]->MakeScript(ctx) + (CScript() << OP_BOOLAND);
            case NodeType::OR_B: return subs[0]->MakeScript(ctx) + subs[1]->MakeScript(ctx) + (CScript() << OP_BOOLOR);
            case NodeType::OR_D: return subs[0]->MakeScript(ctx) + (CScript() << OP_IFDUP << OP_NOTIF) + subs[1]->MakeScript(ctx) + (CScript() << OP_ENDIF);
            case NodeType::OR_C: return subs[0]->MakeScript(ctx) + (CScript() << OP_NOTIF) + subs[1]->MakeScript(ctx) + (CScript() << OP_ENDIF);
            case NodeType::OR_I: return (CScript() << OP_IF) + subs[0]->MakeScript(ctx) + (CScript() << OP_ELSE) + subs[1]->MakeScript(ctx) + (CScript() << OP_ENDIF);
            case NodeType::ANDOR: return subs[0]->MakeScript(ctx) + (CScript() << OP_NOTIF) + subs[2]->MakeScript(ctx) + (CScript() << OP_ELSE) + subs[1]->MakeScript(ctx) + (CScript() << OP_ENDIF);
            case NodeType::THRESH_M: {
                CScript script = CScript() << k;
                for (const auto& key : keys) {
                    script << ctx.ToPKBytes(key);
                }
                return script << keys.size() << (verify ? OP_CHECKMULTISIGVERIFY : OP_CHECKMULTISIG);
            }
            case NodeType::THRESH: {
                CScript script = subs[0]->MakeScript(ctx);
                for (size_t i = 1; i < subs.size(); ++i) {
                    script = (script + subs[i]->MakeScript(ctx)) << OP_ADD;
                }
                return script << k << (verify ? OP_EQUALVERIFY : OP_EQUAL);
            }
        }
        assert(false);
        return {};
    }

    //! Internal code for ToString.
    template<typename Ctx>
    std::string MakeString(const Ctx& ctx, bool wrapped = false) const {
        switch (nodetype) {
            case NodeType::WRAP_A: return "a" + subs[0]->MakeString(ctx, true);
            case NodeType::WRAP_S: return "s" + subs[0]->MakeString(ctx, true);
            case NodeType::WRAP_C: return "c" + subs[0]->MakeString(ctx, true);
            case NodeType::WRAP_D: return "d" + subs[0]->MakeString(ctx, true);
            case NodeType::WRAP_V: return "v" + subs[0]->MakeString(ctx, true);
            case NodeType::WRAP_J: return "j" + subs[0]->MakeString(ctx, true);
            case NodeType::WRAP_N: return "n" + subs[0]->MakeString(ctx, true);
            case NodeType::AND_V:
                // t:X is syntactic sugar for and_v(X,1).
                if (subs[1]->nodetype == NodeType::TRUE) return "t" + subs[0]->MakeString(ctx, true);
                break;
            case NodeType::OR_I:
                if (subs[0]->nodetype == NodeType::FALSE) return "l" + subs[1]->MakeString(ctx, true);
                if (subs[1]->nodetype == NodeType::FALSE) return "u" + subs[0]->MakeString(ctx, true);
                break;
            default:
                break;
        }

        std::string ret = wrapped ? ":" : "";

        switch (nodetype) {
            case NodeType::PK: return std::move(ret) + "pk(" + ctx.ToString(keys[0]) + ")";
            case NodeType::PK_H: return std::move(ret) + "pk_h(" + ctx.ToString(keys[0]) + ")";
            case NodeType::AFTER: return std::move(ret) + "after(" + std::to_string(k) + ")";
            case NodeType::OLDER: return std::move(ret) + "older(" + std::to_string(k) + ")";
            case NodeType::HASH256: return std::move(ret) + "hash256(" + HexStr(data.begin(), data.end()) + ")";
            case NodeType::HASH160: return std::move(ret) + "hash160(" + HexStr(data.begin(), data.end()) + ")";
            case NodeType::SHA256: return std::move(ret) + "sha256(" + HexStr(data.begin(), data.end()) + ")";
            case NodeType::RIPEMD160: return std::move(ret) + "ripemd160(" + HexStr(data.begin(), data.end()) + ")";
            case NodeType::TRUE: return std::move(ret) + "1";
            case NodeType::FALSE: return std::move(ret) + "0";
            case NodeType::AND_V: return std::move(ret) + "and_v(" + subs[0]->MakeString(ctx) + "," + subs[1]->MakeString(ctx) + ")";
            case NodeType::AND_B: return std::move(ret) + "and_b(" + subs[0]->MakeString(ctx) + "," + subs[1]->MakeString(ctx) + ")";
            case NodeType::OR_B: return std::move(ret) + "or_b(" + subs[0]->MakeString(ctx) + "," + subs[1]->MakeString(ctx) + ")";
            case NodeType::OR_D: return std::move(ret) + "or_d(" + subs[0]->MakeString(ctx) + "," + subs[1]->MakeString(ctx) + ")";
            case NodeType::OR_C: return std::move(ret) + "or_c(" + subs[0]->MakeString(ctx) + "," + subs[1]->MakeString(ctx) + ")";
            case NodeType::OR_I: return std::move(ret) + "or_i(" + subs[0]->MakeString(ctx) + "," + subs[1]->MakeString(ctx) + ")";
            case NodeType::ANDOR:
                // and_n(X,Y) is syntactic sugar for andor(X,Y,0).
                if (subs[2]->nodetype == NodeType::FALSE) return std::move(ret) + "and_n(" + subs[0]->MakeString(ctx) + "," + subs[1]->MakeString(ctx) + ")";
                return std::move(ret) + "andor(" + subs[0]->MakeString(ctx) + "," + subs[1]->MakeString(ctx) + "," + subs[2]->MakeString(ctx) + ")";
            case NodeType::THRESH_M: {
                auto str = std::move(ret) + "thresh_m(" + std::to_string(k);
                for (const auto& key : keys) {
                    str += "," + ctx.ToString(key);
                }
                return std::move(str) + ")";
            }
            case NodeType::THRESH: {
                auto str = std::move(ret) + "thresh(" + std::to_string(k);
                for (const auto& sub : subs) {
                    str += "," + sub->MakeString(ctx);
                }
                return std::move(str) + ")";
            }
            default: assert(false); // Wrappers should have been handled above
        }
        return "";
    }

    internal::Ops CalcOps() const {
        switch (nodetype) {
            case NodeType::PK: return {0, 0, 0};
            case NodeType::PK_H: return {3, 0, 0};
            case NodeType::OLDER: return {1, 0, {}};
            case NodeType::AFTER: return {1, 0, {}};
            case NodeType::SHA256: return {4, 0, {}};
            case NodeType::RIPEMD160: return {4, 0, {}};
            case NodeType::HASH256: return {4, 0, {}};
            case NodeType::HASH160: return {4, 0, {}};
            case NodeType::AND_V: return {subs[0]->ops.stat + subs[1]->ops.stat, subs[0]->ops.sat + subs[1]->ops.sat, {}};
            case NodeType::AND_B: return {1 + subs[0]->ops.stat + subs[1]->ops.stat, subs[0]->ops.sat + subs[1]->ops.sat, subs[0]->ops.dsat + subs[1]->ops.dsat};
            case NodeType::OR_B: return {1 + subs[0]->ops.stat + subs[1]->ops.stat, Choose(subs[0]->ops.sat + subs[1]->ops.dsat, subs[1]->ops.sat + subs[0]->ops.dsat), subs[0]->ops.dsat + subs[1]->ops.dsat};
            case NodeType::OR_D: return {3 + subs[0]->ops.stat + subs[1]->ops.stat, Choose(subs[0]->ops.sat, subs[1]->ops.sat + subs[0]->ops.dsat), subs[0]->ops.dsat + subs[1]->ops.dsat};
            case NodeType::OR_C: return {2 + subs[0]->ops.stat + subs[1]->ops.stat, Choose(subs[0]->ops.sat, subs[1]->ops.sat + subs[0]->ops.dsat), {}};
            case NodeType::OR_I: return {3 + subs[0]->ops.stat + subs[1]->ops.stat, Choose(subs[0]->ops.sat, subs[1]->ops.sat), Choose(subs[0]->ops.dsat, subs[1]->ops.dsat)};
            case NodeType::ANDOR: return {3 + subs[0]->ops.stat + subs[1]->ops.stat + subs[2]->ops.stat, Choose(subs[1]->ops.sat + subs[0]->ops.sat, subs[0]->ops.dsat + subs[2]->ops.sat), subs[0]->ops.dsat + subs[2]->ops.dsat};
            case NodeType::THRESH_M: return {1, (uint32_t)keys.size(), (uint32_t)keys.size()};
            case NodeType::WRAP_A: return {2 + subs[0]->ops.stat, subs[0]->ops.sat, subs[0]->ops.dsat};
            case NodeType::WRAP_S: return {1 + subs[0]->ops.stat, subs[0]->ops.sat, subs[0]->ops.dsat};
            case NodeType::WRAP_C: return {1 + subs[0]->ops.stat, subs[0]->ops.sat, subs[0]->ops.dsat};
            case NodeType::WRAP_D: return {3 + subs[0]->ops.stat, subs[0]->ops.sat, 0};
            case NodeType::WRAP_V: return {subs[0]->ops.stat + (subs[0]->GetType() << "x"_mst), subs[0]->ops.sat, {}};
            case NodeType::WRAP_J: return {4 + subs[0]->ops.stat, subs[0]->ops.sat, 0};
            case NodeType::WRAP_N: return {1 + subs[0]->ops.stat, subs[0]->ops.sat, subs[0]->ops.dsat};
            case NodeType::TRUE: return {0, 0, {}};
            case NodeType::FALSE: return {0, {}, 0};
            case NodeType::THRESH: {
                uint32_t stat = 0, dsat = 0;
                int32_t sat_sum = 0;
                std::vector<int32_t> diffs;
                for (const auto& sub : subs) {
                    stat += sub->ops.stat + 1;
                    dsat += sub->ops.dsat.value; // The type system requires "d" for thresh, so dsat must always be valid.
                    if (sub->ops.sat.valid) diffs.push_back((int32_t)sub->ops.sat.value - sub->ops.dsat.value);
                }
                if (diffs.size() < k) return {stat, {}, dsat};
                std::sort(diffs.begin(), diffs.end());
                for (size_t i = diffs.size() - k; i < diffs.size(); ++i) sat_sum += diffs[i];
                return {stat, sat_sum + dsat, dsat};
            }
        }
        assert(false);
        return {0, {}, {}};
    }

    internal::StackSize CalcStackSize() const {
        switch (nodetype) {
            case NodeType::PK: return {1, 1};
            case NodeType::PK_H: return {2, 2};
            case NodeType::OLDER: return {0, {}};
            case NodeType::AFTER: return {0, {}};
            case NodeType::SHA256: return {1, {}};
            case NodeType::RIPEMD160: return {1, {}};
            case NodeType::HASH256: return {1, {}};
            case NodeType::HASH160: return {1, {}};
            case NodeType::ANDOR: return {Choose(subs[0]->ss.sat + subs[1]->ss.sat, subs[0]->ss.dsat + subs[2]->ss.sat), subs[0]->ss.dsat + subs[2]->ss.dsat};
            case NodeType::AND_V: return {subs[0]->ss.sat + subs[1]->ss.sat, {}};
            case NodeType::AND_B: return {subs[0]->ss.sat + subs[1]->ss.sat, subs[0]->ss.dsat + subs[1]->ss.dsat};
            case NodeType::OR_B: return {Choose(subs[0]->ss.dsat + subs[1]->ss.sat, subs[0]->ss.sat + subs[1]->ss.dsat), subs[0]->ss.dsat + subs[1]->ss.dsat};
            case NodeType::OR_C: return {Choose(subs[0]->ss.sat, subs[0]->ss.dsat + subs[1]->ss.sat), {}};
            case NodeType::OR_D: return {Choose(subs[0]->ss.sat, subs[0]->ss.dsat + subs[1]->ss.sat), subs[0]->ss.dsat + subs[1]->ss.dsat};
            case NodeType::OR_I: return {Choose(subs[0]->ss.sat + 1, subs[1]->ss.sat + 1), Choose(subs[0]->ss.dsat + 1, subs[1]->ss.dsat + 1)};
            case NodeType::THRESH_M: return {(uint32_t)keys.size() + 1, (uint32_t)keys.size() + 1};
            case NodeType::WRAP_A: return subs[0]->ss;
            case NodeType::WRAP_S: return subs[0]->ss;
            case NodeType::WRAP_C: return subs[0]->ss;
            case NodeType::WRAP_D: return {1 + subs[0]->ss.sat, 1};
            case NodeType::WRAP_V: return {subs[0]->ss.sat, {}};
            case NodeType::WRAP_J: return {subs[0]->ss.sat, 1};
            case NodeType::WRAP_N: return subs[0]->ss;
            case NodeType::TRUE: return {0, {}};
            case NodeType::FALSE: return {{}, 0};
            case NodeType::THRESH: {
                uint32_t dsat = 0;
                int32_t sat_sum = 0;
                std::vector<int32_t> diffs;
                for (const auto& sub : subs) {
                    dsat += sub->ss.dsat.value; // The type system requires "d" for thresh, so dsat must always be valid.
                    if (sub->ss.sat.valid) diffs.push_back((int32_t)sub->ss.sat.value - sub->ss.dsat.value);
                }
                if (diffs.size() < k) return {{}, dsat};
                std::sort(diffs.begin(), diffs.end());
                for (size_t i = diffs.size() - k; i < diffs.size(); ++i) sat_sum += diffs[i];
                return {sat_sum + dsat, dsat};
            }
        }
        assert(false);
        return {{}, {}};
    }

    template<typename Ctx>
    internal::InputResult ProduceInput(const Ctx& ctx, bool nonmal) const {
        auto ret = ProduceInputHelper(ctx, nonmal);
        // Do a consistency check between the satisfaction code and the type checker
        // (the actual satisfaction code in ProduceInputHelper does not use GetType)
        if (GetType() << "z"_mst && ret.nsat.valid) assert(ret.nsat.stack.size() == 0);
        if (GetType() << "z"_mst && ret.sat.valid) assert(ret.sat.stack.size() == 0);
        if (GetType() << "o"_mst && ret.nsat.valid) assert(ret.nsat.stack.size() == 1);
        if (GetType() << "o"_mst && ret.sat.valid) assert(ret.sat.stack.size() == 1);
        if (GetType() << "n"_mst && ret.sat.valid) assert(ret.sat.stack.back().size() != 0);
        if (GetType() << "d"_mst) assert(ret.nsat.valid);
        if (GetType() << "f"_mst && ret.nsat.valid) assert(ret.nsat.has_sig);
        if (GetType() << "s"_mst && ret.sat.valid) assert(ret.sat.has_sig);
        if (nonmal) {
            if (GetType() << "d"_mst) assert(!ret.nsat.has_sig);
            if (GetType() << "d"_mst && !ret.nsat.malleable) assert(!ret.nsat.non_canon);
            if (GetType() << "e"_mst) assert(!ret.nsat.malleable);
            if (GetType() << "m"_mst && ret.sat.valid) assert(!ret.sat.malleable);
            if (ret.sat.valid && !ret.sat.malleable) assert(!ret.sat.non_canon);
        }
        return ret;
    }

    template<typename Ctx>
    internal::InputResult ProduceInputHelper(const Ctx& ctx, bool nonmal) const {
        using namespace internal;

        const auto ZERO = InputStack(std::vector<unsigned char>());
        const auto ZERO32 = InputStack(std::vector<unsigned char>(32, 0)).Malleable();
        const auto ONE = InputStack(Vector((unsigned char)1));
        const auto EMPTY = InputStack(true);
        const auto MALLEABLE_EMPTY = InputStack(true).Malleable();
        const auto INVALID = InputStack(false);

        switch (nodetype) {
            case NodeType::PK: {
                std::vector<unsigned char> sig;
                if (!ctx.Sign(keys[0], sig)) return InputResult(ZERO, INVALID);
                return InputResult(ZERO, InputStack(std::move(sig)).WithSig());
            }
            case NodeType::PK_H: {
                std::vector<unsigned char> key = ctx.ToPKBytes(keys[0]), sig;
                if (!ctx.Sign(keys[0], sig)) return InputResult(ZERO + InputStack(std::move(key)), INVALID);
                return InputResult(ZERO + InputStack(key), InputStack(std::move(sig)).WithSig() + InputStack(key));
            }
            case NodeType::THRESH_M: {
                InputStack sat = ZERO;
                InputStack nsat = ZERO;
                uint32_t good = 0;
                for (uint32_t i = 0; i < k; ++i) nsat = std::move(nsat) + ZERO;
                for (size_t i = 0; i < keys.size(); ++i) {
                    std::vector<unsigned char> sig;
                    if (ctx.Sign(keys[i], sig)) {
                        sat = std::move(sat) + InputStack(std::move(sig)).WithSig();
                        ++good;
                        if (good == k) break;
                    }
                }
                if (good == k) return InputResult(std::move(nsat), std::move(sat));
                return InputResult(std::move(nsat), INVALID);
            }
            case NodeType::OLDER: {
                return InputResult(INVALID, ctx.CheckOlder(k) ? EMPTY : INVALID);
            }
            case NodeType::AFTER: {
                return InputResult(INVALID, ctx.CheckAfter(k) ? EMPTY : INVALID);
            }
            case NodeType::SHA256: {
                std::vector<unsigned char> preimage;
                if (!ctx.SatSHA256(data, preimage)) return InputResult(ZERO32, INVALID);
                return InputResult(ZERO32, std::move(preimage));
            }
            case NodeType::RIPEMD160: {
                std::vector<unsigned char> preimage;
                if (!ctx.SatRIPEMD160(data, preimage)) return InputResult(ZERO32, INVALID);
                return InputResult(ZERO32, std::move(preimage));
            }
            case NodeType::HASH256: {
                std::vector<unsigned char> preimage;
                if (!ctx.SatHASH256(data, preimage)) return InputResult(ZERO32, INVALID);
                return InputResult(ZERO32, std::move(preimage));
            }
            case NodeType::HASH160: {
                std::vector<unsigned char> preimage;
                if (!ctx.SatHASH160(data, preimage)) return InputResult(ZERO32, INVALID);
                return InputResult(ZERO32, std::move(preimage));
            }
            case NodeType::AND_V: {
                auto x = subs[0]->ProduceInput(ctx, nonmal), y = subs[1]->ProduceInput(ctx, nonmal);
                return InputResult((y.nsat + x.sat).NonCanon(), y.sat + x.sat);
            }
            case NodeType::AND_B: {
                auto x = subs[0]->ProduceInput(ctx, nonmal), y = subs[1]->ProduceInput(ctx, nonmal);
                return InputResult(Choose(Choose(y.nsat + x.nsat, (y.sat + x.nsat).NonCanon(), nonmal), (y.nsat + x.sat).NonCanon(), nonmal), y.sat + x.sat);
            }
            case NodeType::OR_B: {
                auto x = subs[0]->ProduceInput(ctx, nonmal), z = subs[1]->ProduceInput(ctx, nonmal);
                return InputResult(z.nsat + x.nsat, Choose(Choose(z.nsat + x.sat, z.sat + x.nsat, nonmal), (z.sat + x.sat).NonCanon(), nonmal));
            }
            case NodeType::OR_C: {
                auto x = subs[0]->ProduceInput(ctx, nonmal), z = subs[1]->ProduceInput(ctx, nonmal);
                return InputResult(INVALID, Choose(x.sat, z.sat + x.nsat, nonmal));
            }
            case NodeType::OR_D: {
                auto x = subs[0]->ProduceInput(ctx, nonmal), z = subs[1]->ProduceInput(ctx, nonmal);
                auto nsat = z.nsat + x.nsat, sat_l = x.sat, sat_r = z.sat + x.nsat;
                return InputResult(z.nsat + x.nsat, Choose(x.sat, z.sat + x.nsat, nonmal));
            }
            case NodeType::OR_I: {
                auto x = subs[0]->ProduceInput(ctx, nonmal), z = subs[1]->ProduceInput(ctx, nonmal);
                return InputResult(Choose(x.nsat + ONE, z.nsat + ZERO, nonmal), Choose(x.sat + ONE, z.sat + ZERO, nonmal));
            }
            case NodeType::ANDOR: {
                auto x = subs[0]->ProduceInput(ctx, nonmal), y = subs[1]->ProduceInput(ctx, nonmal), z = subs[2]->ProduceInput(ctx, nonmal);
                return InputResult(Choose((y.nsat + x.sat).NonCanon(), z.nsat + x.nsat, nonmal), Choose(y.sat + x.sat, z.sat + x.nsat, nonmal));
            }
            case NodeType::WRAP_A:
            case NodeType::WRAP_S:
            case NodeType::WRAP_C:
            case NodeType::WRAP_N:
                return subs[0]->ProduceInput(ctx, nonmal);
            case NodeType::WRAP_D: {
                auto x = subs[0]->ProduceInput(ctx, nonmal);
                return InputResult(ZERO, x.sat + ONE);
            }
            case NodeType::WRAP_J: {
                auto x = subs[0]->ProduceInput(ctx, nonmal);
                // If a dissatisfaction with a nonzero top stack element exists, an alternative dissatisfaction exists.
                // As the dissatisfaction logic currently doesn't keep track of this nonzeroness property, and thus even
                // if a dissatisfaction with a top zero element is found, we don't know whether another one with a
                // nonzero top stack element exists. Make the conservative assumption that whenever the subexpression is weakly
                // dissatisfiable, this alternative dissatisfaction exists and leads to malleability.
                return InputResult(InputStack(ZERO).Malleable(x.nsat.valid && !x.nsat.has_sig), x.sat);
            }
            case NodeType::WRAP_V: {
                auto x = subs[0]->ProduceInput(ctx, nonmal);
                return InputResult(INVALID, x.sat);
            }
            case NodeType::FALSE: return InputResult(EMPTY, INVALID);
            case NodeType::TRUE: return InputResult(INVALID, EMPTY);
            case NodeType::THRESH: {
                std::vector<InputResult> sub;
                std::vector<bool> choice(subs.size(), false);
                std::vector<std::pair<int64_t, size_t>> costs;
                int to_add = k;
                for (size_t i = 0; i < subs.size(); ++i) {
                    sub.push_back(subs[i]->ProduceInput(ctx, nonmal));
                    assert(sub.back().nsat.valid);
                    costs.emplace_back((int64_t)sub.back().sat.size - sub.back().nsat.size, i);
                }
                std::sort(costs.begin(), costs.end());
                if (nonmal) {
                    // First add all weak subexpressions (to_add will go negative if k is too low to add them all)
                    for (size_t i = 0; i < subs.size(); ++i) {
                        if (sub[costs[i].second].sat.valid && !sub[costs[i].second].sat.has_sig) {
                            if (to_add > 0) choice[costs[i].second] = true;
                            to_add--;
                        }
                    }
                    // Then add subexpressions whose satisfaction is nonmalleable but their nonsatisfaction is malleable.
                    for (size_t i = 0; i < subs.size() && to_add > 0; ++i) {
                        if (!choice[costs[i].second] && sub[costs[i].second].sat.valid && !sub[costs[i].second].sat.malleable && sub[costs[i].second].nsat.malleable) {
                            choice[costs[i].second] = true;
                            to_add--;
                        }
                    }
                    // Then all other subexpressions with nonmalleable satisfaction.
                    for (size_t i = 0; i < subs.size() && to_add > 0; ++i) {
                        if (!choice[costs[i].second] && sub[costs[i].second].sat.valid && !sub[costs[i].second].sat.malleable) {
                            choice[costs[i].second] = true;
                            to_add--;
                        }
                    }
                } else {
                    // Just pick the overall cheapest ones.
                    for (size_t i = 0; i < subs.size() && to_add > 0; ++i) {
                        if (sub[costs[i].second].sat.valid && !choice[costs[i].second]) {
                            choice[costs[i].second] = true;
                            to_add--;
                        }
                    }
                }
                InputStack sat = to_add > 0 ? INVALID : to_add < 0 ? MALLEABLE_EMPTY : EMPTY;
                InputStack nsat = EMPTY;
                for (size_t i = 0; i < subs.size(); ++i) {
                    if (choice[subs.size() - 1 - i]) {
                        sat = sat + sub[subs.size() - 1 - i].sat;
                    } else {
                        sat = sat + sub[subs.size() - 1 - i].nsat;
                    }
                    nsat = nsat + sub[subs.size() - 1 - i].nsat;
                }
                return InputResult(nsat, sat);
            }
        }
        assert(false);
        return InputResult(INVALID, INVALID);
    }

public:
    //! Return the size of the script for this expression (faster than ToString().size()).
    size_t ScriptSize() const { return scriptlen; }

    //! Return the maximum number of ops needed to satisfy this script non-malleably.
    uint32_t GetOps() const { return ops.stat + ops.sat.value; }

    //! Check the ops limit of this script.
    bool CheckOpsLimit() const { return GetOps() <= MAX_OPS_PER_SCRIPT; }

    //! Return the maximum number of stack elements needed to satisfy this script non-malleably.
    uint32_t GetStackSize() const { return ss.sat.value; }

    //! Return the expression type.
    Type GetType() const { return typ; }

    //! Construct the script for this miniscript (including subexpressions).
    template<typename Ctx>
    CScript ToScript(const Ctx& ctx) const { return MakeScript(ctx); }

    //! Convert this miniscript to its textual descriptor notation.
    template<typename Ctx>
    std::string ToString(const Ctx& ctx) const { return MakeString(ctx); }

    template<typename Ctx>
    bool Satisfy(const Ctx& ctx, std::vector<std::vector<unsigned char>>& stack, bool nonmalleable = true) const {
        auto ret = ProduceInput(ctx, nonmalleable);
        if (nonmalleable && (ret.sat.malleable || !ret.sat.has_sig)) return false;
        stack = std::move(ret.sat.stack);
        return ret.sat.valid;
    }

    //! Equality testing.
    bool operator==(const Node<Key>& arg) const
    {
        if (nodetype != arg.nodetype) return false;
        if (k != arg.k) return false;
        if (data != arg.data) return false;
        if (keys != arg.keys) return false;
        if (subs.size() != arg.subs.size()) return false;
        for (size_t i = 0; i < subs.size(); ++i) {
            if (!(*subs[i] == *arg.subs[i])) return false;
        }
        assert(scriptlen == arg.scriptlen);
        assert(typ == arg.typ);
        return true;
    }

    // Constructors with various argument combinations.
    Node(NodeType nt, std::vector<NodeRef<Key>> sub, std::vector<unsigned char> arg, uint32_t val = 0) : nodetype(nt), k(val), data(std::move(arg)), subs(std::move(sub)), ops(CalcOps()), ss(CalcStackSize()), typ(CalcType()), scriptlen(CalcScriptLen()), types(CalcTypes()) {}
    Node(NodeType nt, std::vector<unsigned char> arg, uint32_t val = 0) : nodetype(nt), k(val), data(std::move(arg)), ops(CalcOps()), ss(CalcStackSize()), typ(CalcType()), scriptlen(CalcScriptLen()), types(CalcTypes()) {}
    Node(NodeType nt, std::vector<NodeRef<Key>> sub, std::vector<Key> key, uint32_t val = 0) : nodetype(nt), k(val), keys(std::move(key)), subs(std::move(sub)), ops(CalcOps()), ss(CalcStackSize()), typ(CalcType()), scriptlen(CalcScriptLen()), types(CalcTypes()) {}
    Node(NodeType nt, std::vector<Key> key, uint32_t val = 0) : nodetype(nt), k(val), keys(std::move(key)), ops(CalcOps()), ss(CalcStackSize()), typ(CalcType()), scriptlen(CalcScriptLen()), types(CalcTypes()) {}
    Node(NodeType nt, std::vector<NodeRef<Key>> sub, uint32_t val = 0) : nodetype(nt), k(val), subs(std::move(sub)), ops(CalcOps()), ss(CalcStackSize()), typ(CalcType()), scriptlen(CalcScriptLen()), types(CalcTypes()) {}
    Node(NodeType nt, uint32_t val = 0) : nodetype(nt), k(val), ops(CalcOps()), ss(CalcStackSize()), typ(CalcType()), scriptlen(CalcScriptLen()), types(CalcTypes()) {}
};

namespace internal {

//! Parse a miniscript from its textual descriptor form.
template<typename Key, typename Ctx>
inline NodeRef<Key> Parse(Span<const char>& in, const Ctx& ctx) {
    auto expr = Expr(in);
    // Parse wrappers
    for (int i = 0; i < expr.size(); ++i) {
        if (expr[i] == ':') {
            auto in2 = expr.subspan(i + 1);
            auto sub = Parse<Key>(in2, ctx);
            if (!sub || in2.size()) return {};
            for (size_t j = i; j-- > 0; ) {
                if (expr[j] == 'a') {
                    sub = MakeNodeRef<Key>(NodeType::WRAP_A, Vector(std::move(sub)));
                } else if (expr[j] == 's') {
                    sub = MakeNodeRef<Key>(NodeType::WRAP_S, Vector(std::move(sub)));
                } else if (expr[j] == 'c') {
                    sub = MakeNodeRef<Key>(NodeType::WRAP_C, Vector(std::move(sub)));
                } else if (expr[j] == 'd') {
                    sub = MakeNodeRef<Key>(NodeType::WRAP_D, Vector(std::move(sub)));
                } else if (expr[j] == 'j') {
                    sub = MakeNodeRef<Key>(NodeType::WRAP_J, Vector(std::move(sub)));
                } else if (expr[j] == 'n') {
                    sub = MakeNodeRef<Key>(NodeType::WRAP_N, Vector(std::move(sub)));
                } else if (expr[j] == 'v') {
                    sub = MakeNodeRef<Key>(NodeType::WRAP_V, Vector(std::move(sub)));
                } else if (expr[j] == 't') {
                    sub = MakeNodeRef<Key>(NodeType::AND_V, Vector(std::move(sub), MakeNodeRef<Key>(NodeType::TRUE)));
                } else if (expr[j] == 'u') {
                    sub = MakeNodeRef<Key>(NodeType::OR_I, Vector(std::move(sub), MakeNodeRef<Key>(NodeType::FALSE)));
                } else if (expr[j] == 'l') {
                    sub = MakeNodeRef<Key>(NodeType::OR_I, Vector(MakeNodeRef<Key>(NodeType::FALSE), std::move(sub)));
                } else {
                    return {};
                }
            }
            return sub;
        }
        if (expr[i] < 'a' || expr[i] > 'z') break;
    }
    // Parse the other node types
    NodeType nodetype;
    if (expr == Span<const char>("0", 1)) {
        return MakeNodeRef<Key>(NodeType::FALSE);
    } else if (expr == Span<const char>("1", 1)) {
        return MakeNodeRef<Key>(NodeType::TRUE);
    } else if (Func("pk", expr)) {
        Key key;
        if (ctx.FromString(expr.begin(), expr.end(), key)) {
            return MakeNodeRef<Key>(NodeType::PK, Vector(std::move(key)));
        }
        return {};
    } else if (Func("pk_h", expr)) {
        Key key;
        if (ctx.FromString(expr.begin(), expr.end(), key)) {
            return MakeNodeRef<Key>(NodeType::PK_H, Vector(std::move(key)));
        }
        return {};
    } else if (expr == MakeSpan("0")) {
        return MakeNodeRef<Key>(NodeType::FALSE);
    } else if (expr == MakeSpan("1")) {
        return MakeNodeRef<Key>(NodeType::TRUE);
    } else if (Func("sha256", expr)) {
        auto hash = ParseHex(std::string(expr.begin(), expr.end()));
        if (hash.size() != 32) return {};
        return MakeNodeRef<Key>(NodeType::SHA256, std::move(hash));
    } else if (Func("ripemd160", expr)) {
        auto hash = ParseHex(std::string(expr.begin(), expr.end()));
        if (hash.size() != 20) return {};
        return MakeNodeRef<Key>(NodeType::RIPEMD160, std::move(hash));
    } else if (Func("hash256", expr)) {
        auto hash = ParseHex(std::string(expr.begin(), expr.end()));
        if (hash.size() != 32) return {};
        return MakeNodeRef<Key>(NodeType::HASH256, std::move(hash));
    } else if (Func("hash160", expr)) {
        auto hash = ParseHex(std::string(expr.begin(), expr.end()));
        if (hash.size() != 20) return {};
        return MakeNodeRef<Key>(NodeType::HASH160, std::move(hash));
    } else if (Func("after", expr)) {
        unsigned long num = std::stoul(std::string(expr.begin(), expr.end()));
        if (num < 1 || num >= 0x80000000UL) return {};
        return MakeNodeRef<Key>(NodeType::AFTER, num);
    } else if (Func("older", expr)) {
        unsigned long num = std::stoul(std::string(expr.begin(), expr.end()));
        if (num < 1 || num >= 0x80000000UL) return {};
        return MakeNodeRef<Key>(NodeType::OLDER, num);
    } else if (Func("and_n", expr)) {
        auto left = Parse<Key>(expr, ctx);
        if (!left || !Const(",", expr)) return {};
        auto right = Parse<Key>(expr, ctx);
        if (!right || expr.size()) return {};
        return MakeNodeRef<Key>(NodeType::ANDOR, Vector(std::move(left), std::move(right), MakeNodeRef<Key>(NodeType::FALSE)));
    } else if (Func("andor", expr)) {
        auto left = Parse<Key>(expr, ctx);
        if (!left || !Const(",", expr)) return {};
        auto mid = Parse<Key>(expr, ctx);
        if (!mid || !Const(",", expr)) return {};
        auto right = Parse<Key>(expr, ctx);
        if (!right || expr.size()) return {};
        return MakeNodeRef<Key>(NodeType::ANDOR, Vector(std::move(left), std::move(mid), std::move(right)));
    } else if (Func("thresh_m", expr)) {
        auto arg = Expr(expr);
        uint32_t count = std::stoul(std::string(arg.begin(), arg.end()));
        std::vector<Key> keys;
        while (expr.size()) {
            if (!Const(",", expr)) return {};
            auto keyarg = Expr(expr);
            Key key;
            if (!ctx.FromString(keyarg.begin(), keyarg.end(), key)) return {};
            keys.push_back(std::move(key));
        }
        if (keys.size() < 1 || keys.size() > 20) return {};
        if (count < 1 || count > keys.size()) return {};
        return MakeNodeRef<Key>(NodeType::THRESH_M, std::move(keys), count);
    } else if (Func("thresh", expr)) {
        auto arg = Expr(expr);
        uint32_t count = std::stoul(std::string(arg.begin(), arg.end()));
        std::vector<NodeRef<Key>> subs;
        while (expr.size()) {
            if (!Const(",", expr)) return {};
            auto sub = Parse<Key>(expr, ctx);
            if (!sub) return {};
            subs.push_back(std::move(sub));
        }
        if (count <= 1 || count >= subs.size()) return {};
        return MakeNodeRef<Key>(NodeType::THRESH, std::move(subs), count);
    } else if (Func("and_v", expr)) {
        nodetype = NodeType::AND_V;
    } else if (Func("and_b", expr)) {
        nodetype = NodeType::AND_B;
    } else if (Func("or_c", expr)) {
        nodetype = NodeType::OR_C;
    } else if (Func("or_b", expr)) {
        nodetype = NodeType::OR_B;
    } else if (Func("or_d", expr)) {
        nodetype = NodeType::OR_D;
    } else if (Func("or_i", expr)) {
        nodetype = NodeType::OR_I;
    } else {
        return {};
    }
    auto left = Parse<Key>(expr, ctx);
    if (!left || !Const(",", expr)) return {};
    auto right = Parse<Key>(expr, ctx);
    if (!right || expr.size()) return {};
    return MakeNodeRef<Key>(nodetype, Vector(std::move(left), std::move(right)));
}

/** Decode a script into opcode/push pairs.
 *
 * Construct a vector with one element per opcode in the script, in reverse order.
 * Each element is a pair consisting of the opcode, as well as the data pushed by
 * the opcode (including OP_n), if any. OP_CHECKSIGVERIFY, OP_CHECKMULTISIGVERIFY,
 * and OP_EQUALVERIFY are decomposed into OP_CHECKSIG, OP_CHECKMULTISIG, OP_EQUAL
 * respectively, plus OP_VERIFY.
 */
bool DecomposeScript(const CScript& script, std::vector<std::pair<opcodetype, std::vector<unsigned char>>>& out);

/** Determine whether the passed pair (created by DecomposeScript) is pushing a number. */
bool ParseScriptNumber(const std::pair<opcodetype, std::vector<unsigned char>>& in, int64_t& k);

template<typename Key, typename Ctx, typename I> inline NodeRef<Key> DecodeSingle(I& in, I last, const Ctx& ctx);
template<typename Key, typename Ctx, typename I> inline NodeRef<Key> DecodeMulti(I& in, I last, const Ctx& ctx);
template<typename Key, typename Ctx, typename I> inline NodeRef<Key> DecodeWrapped(I& in, I last, const Ctx& ctx);

//! Decode a list of script elements into a miniscript (except and_v, s:, and a:).
template<typename Key, typename Ctx, typename I>
inline NodeRef<Key> DecodeSingle(I& in, I last, const Ctx& ctx) {
    std::vector<NodeRef<Key>> subs;
    std::vector<Key> keys;
    int64_t k;

    if (last > in && in[0].first == OP_1) {
        ++in;
        return MakeNodeRef<Key>(NodeType::TRUE);
    }
    if (last > in && in[0].first == OP_0) {
        ++in;
        return MakeNodeRef<Key>(NodeType::FALSE);
    }
    if (last > in && in[0].second.size() == 33) {
        Key key;
        if (!ctx.FromPKBytes(in[0].second.begin(), in[0].second.end(), key)) return {};
        ++in;
        return MakeNodeRef<Key>(NodeType::PK, Vector(std::move(key)));
    }
    if (last - in >= 5 && in[0].first == OP_VERIFY && in[1].first == OP_EQUAL && in[3].first == OP_HASH160 && in[4].first == OP_DUP && in[2].second.size() == 20) {
        Key key;
        if (!ctx.FromPKHBytes(in[2].second.begin(), in[2].second.end(), key)) return {};
        in += 5;
        return MakeNodeRef<Key>(NodeType::PK_H, Vector(std::move(key)));
    }
    if (last - in >= 2 && in[0].first == OP_CHECKSEQUENCEVERIFY && ParseScriptNumber(in[1], k)) {
        in += 2;
        if (k < 1 || k > 0x7FFFFFFFL) return {};
        return MakeNodeRef<Key>(NodeType::OLDER, k);
    }
    if (last - in >= 2 && in[0].first == OP_CHECKLOCKTIMEVERIFY && ParseScriptNumber(in[1], k)) {
        in += 2;
        if (k < 1 || k > 0x7FFFFFFFL) return {};
        return MakeNodeRef<Key>(NodeType::AFTER, k);
    }
    if (last - in >= 7 && in[0].first == OP_EQUAL && in[1].second.size() == 32 && in[2].first == OP_SHA256 && in[3].first == OP_VERIFY && in[4].first == OP_EQUAL && ParseScriptNumber(in[5], k) && k == 32 && in[6].first == OP_SIZE) {
        in += 7;
        return MakeNodeRef<Key>(NodeType::SHA256, in[-6].second);
    }
    if (last - in >= 7 && in[0].first == OP_EQUAL && in[1].second.size() == 20 && in[2].first == OP_RIPEMD160 && in[3].first == OP_VERIFY && in[4].first == OP_EQUAL && ParseScriptNumber(in[5], k) && k == 32 && in[6].first == OP_SIZE) {
        in += 7;
        return MakeNodeRef<Key>(NodeType::RIPEMD160, in[-6].second);
    }
    if (last - in >= 7 && in[0].first == OP_EQUAL && in[1].second.size() == 32 && in[2].first == OP_HASH256 && in[3].first == OP_VERIFY && in[4].first == OP_EQUAL && ParseScriptNumber(in[5], k) && k == 32 && in[6].first == OP_SIZE) {
        in += 7;
        return MakeNodeRef<Key>(NodeType::HASH256, in[-6].second);
    }
    if (last - in >= 7 && in[0].first == OP_EQUAL && in[1].second.size() == 20 && in[2].first == OP_HASH160 && in[3].first == OP_VERIFY && in[4].first == OP_EQUAL && ParseScriptNumber(in[5], k) && k == 32 && in[6].first == OP_SIZE) {
        in += 7;
        return MakeNodeRef<Key>(NodeType::HASH160, in[-6].second);
    }
    if (last - in >= 2 && in[0].first == OP_CHECKSIG) {
        ++in;
        auto sub = DecodeSingle<Key>(in, last, ctx);
        if (!sub) return {};
        return MakeNodeRef<Key>(NodeType::WRAP_C, Vector(std::move(sub)));
    }
    if (last - in >= 3 && in[0].first == OP_BOOLAND) {
        ++in;
        auto sub1 = DecodeWrapped<Key>(in, last, ctx);
        if (!sub1) return {};
        auto sub2 = DecodeSingle<Key>(in, last, ctx);
        if (!sub2) return {};
        return MakeNodeRef<Key>(NodeType::AND_B, Vector(std::move(sub2), std::move(sub1)));
    }
    if (last - in >= 3 && in[0].first == OP_BOOLOR) {
        ++in;
        auto sub1 = DecodeWrapped<Key>(in, last, ctx);
        if (!sub1) return {};
        auto sub2 = DecodeSingle<Key>(in, last, ctx);
        if (!sub2) return {};
        return MakeNodeRef<Key>(NodeType::OR_B, Vector(std::move(sub2), std::move(sub1)));
    }
    if (last - in >= 2 && in[0].first == OP_VERIFY) {
        ++in;
        auto sub = DecodeSingle<Key>(in, last, ctx);
        if (!sub) return {};
        return MakeNodeRef<Key>(NodeType::WRAP_V, Vector(std::move(sub)));
    }
    if (last - in >= 2 && in[0].first == OP_0NOTEQUAL) {
        ++in;
        auto sub = DecodeSingle<Key>(in, last, ctx);
        if (!sub) return {};
        return MakeNodeRef<Key>(NodeType::WRAP_N, Vector(std::move(sub)));
    }
    if (last > in && in[0].first == OP_ENDIF) {
        ++in;
        if (last - in == 0) return {};
        NodeRef<Key> sub1;
        sub1 = DecodeMulti<Key>(in, last, ctx);
        if (!sub1) return {};
        bool have_else = false;
        NodeRef<Key> sub2;
        if (last - in == 0) return {};
        if (in[0].first == OP_ELSE) {
            ++in;
            have_else = true;
            sub2 = DecodeMulti<Key>(in, last, ctx);
            if (!sub2) return {};
        }
        if (last - in == 0 || (in[0].first != OP_IF && in[0].first != OP_NOTIF)) return {};
        bool negated = (in[0].first == OP_NOTIF);
        ++in;

        if (!have_else && !negated) {
            if (last > in && in[0].first == OP_DUP) {
                ++in;
                return MakeNodeRef<Key>(NodeType::WRAP_D, Vector(std::move(sub1)));
            }
            if (last - in >= 2 && in[0].first == OP_0NOTEQUAL && in[1].first == OP_SIZE) {
                in += 2;
                return MakeNodeRef<Key>(NodeType::WRAP_J, Vector(std::move(sub1)));
            }
            return {};
        }
        if (have_else && negated) {
            auto sub3 = DecodeSingle<Key>(in, last, ctx);
            if (!sub3) return {};
            return MakeNodeRef<Key>(NodeType::ANDOR, Vector(std::move(sub3), std::move(sub1), std::move(sub2)));
        }
        if (!have_else && negated) {
            if (last - in >= 2 && in[0].first == OP_IFDUP) {
                ++in;
                auto sub3 = DecodeSingle<Key>(in, last, ctx);
                if (!sub3) return {};
                return MakeNodeRef<Key>(NodeType::OR_D, Vector(std::move(sub3), std::move(sub1)));
            }
            if (last > in) {
                auto sub3 = DecodeSingle<Key>(in, last, ctx);
                if (!sub3) return {};
                return MakeNodeRef<Key>(NodeType::OR_C, Vector(std::move(sub3), std::move(sub1)));
            }
            return {};
        }
        if (have_else && !negated) {
            return MakeNodeRef<Key>(NodeType::OR_I, Vector(std::move(sub2), std::move(sub1)));
        }
        return {};
    }
    keys.clear();
    if (last - in >= 3 && in[0].first == OP_CHECKMULTISIG) {
        int64_t n;
        if (!ParseScriptNumber(in[1], n)) return {};
        if (last - in < 3 + n) return {};
        if (n < 1 || n > 20) return {};
        for (int i = 0; i < n; ++i) {
            Key key;
            if (in[2 + i].second.size() != 33) return {};
            if (!ctx.FromPKBytes(in[2 + i].second.begin(), in[2 + i].second.end(), key)) return {};
            keys.push_back(std::move(key));
        }
        if (!ParseScriptNumber(in[2 + n], k)) return {};
        if (k < 1 || k > n) return {};
        in += 3 + n;
        std::reverse(keys.begin(), keys.end());
        return MakeNodeRef<Key>(NodeType::THRESH_M, std::move(keys), k);
    }
    subs.clear();
    if (last - in >= 3 && in[0].first == OP_EQUAL && ParseScriptNumber(in[1], k)) {
        in += 2;
        while (last - in >= 2 && in[0].first == OP_ADD) {
            ++in;
            auto sub = DecodeWrapped<Key>(in, last, ctx);
            if (!sub) return {};
            subs.push_back(std::move(sub));
        }
        auto sub = DecodeSingle<Key>(in, last, ctx);
        if (!sub) return {};
        subs.push_back(std::move(sub));
        std::reverse(subs.begin(), subs.end());
        return MakeNodeRef<Key>(NodeType::THRESH, std::move(subs), k);
    }

    return {};
}

//! Decode a list of script elements into a miniscript (except a: and s:)
template<typename Key, typename Ctx, typename I>
inline NodeRef<Key> DecodeMulti(I& in, I last, const Ctx& ctx) {
    if (in == last) return {};
    auto sub = DecodeSingle<Key>(in, last, ctx);
    if (!sub) return {};
    while (in != last && in[0].first != OP_ELSE && in[0].first != OP_IF && in[0].first != OP_NOTIF && in[0].first != OP_TOALTSTACK && in[0].first != OP_SWAP) {
        auto sub2 = DecodeSingle<Key>(in, last, ctx);
        if (!sub2) return {};
        sub = MakeNodeRef<Key>(NodeType::AND_V, Vector(std::move(sub2), std::move(sub)));
    }
    return sub;
}

//! Decode a list of script elements into a miniscript (only a: and s:)
template<typename Key, typename Ctx, typename I>
inline NodeRef<Key> DecodeWrapped(I& in, I last, const Ctx& ctx) {
    if (last - in >= 3 && in[0].first == OP_FROMALTSTACK) {
        ++in;
        auto sub = DecodeMulti<Key>(in, last, ctx);
        if (!sub) return {};
        if (in == last || in[0].first != OP_TOALTSTACK) return {};
        ++in;
        return MakeNodeRef<Key>(NodeType::WRAP_A, Vector(std::move(sub)));
    }
    auto sub = DecodeMulti<Key>(in, last, ctx);
    if (!sub) return {};
    if (in == last || in[0].first != OP_SWAP) return {};
    ++in;
    return MakeNodeRef<Key>(NodeType::WRAP_S, Vector(std::move(sub)));
}

} // namespace internal

template<typename Ctx>
inline NodeRef<typename Ctx::Key> FromString(const std::string& str, const Ctx& ctx) {
    using namespace internal;
    Span<const char> span = MakeSpan(str);
    auto ret = Parse<typename Ctx::Key>(span, ctx);
    if (!ret || span.size()) return {};
//    if (!(ret->GetType() << "B"_mst)) return {};
    return ret;
}

template<typename Ctx>
inline NodeRef<typename Ctx::Key> FromScript(const CScript& script, const Ctx& ctx) {
    using namespace internal;
    std::vector<std::pair<opcodetype, std::vector<unsigned char>>> decomposed;
    if (!DecomposeScript(script, decomposed)) return {};
    auto it = decomposed.begin();
    auto ret = DecodeMulti<typename Ctx::Key>(it, decomposed.end(), ctx);
    if (!ret) return {};
    if (!(ret->GetType() << "B"_mst)) return {};
    if (it != decomposed.end()) return {};
    return ret;
}

} // namespace miniscript

#endif
