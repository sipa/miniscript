// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>
#include <script/script.h>
#include <script/miniscript.h>

#include <assert.h>

namespace miniscript {
namespace internal {

Type SanitizeType(Type e) {
    int num_types = (e << "K"_mst) + (e << "V"_mst) + (e << "B"_mst) + (e << "W"_mst);
    if (num_types == 0) return ""_mst; // No valid type, don't care about the rest
    assert(num_types == 1); // K, V, B, W all conflict with each other
    assert(!(e << "z"_mst) || !(e << "o"_mst)); // z conflicts with o
    assert(!(e << "n"_mst) || !(e << "z"_mst)); // n conflicts with z
    assert(!(e << "V"_mst) || !(e << "d"_mst)); // V conflicts with d
    assert(!(e << "K"_mst) ||  (e << "u"_mst)); // K implies u
    assert(!(e << "V"_mst) || !(e << "u"_mst)); // V conflicts with u
    assert(!(e << "e"_mst) || !(e << "f"_mst)); // e conflicts with f
    assert(!(e << "e"_mst) ||  (e << "d"_mst)); // e implies d
    assert(!(e << "V"_mst) || !(e << "e"_mst)); // V conflicts with e
    assert(!(e << "d"_mst) || !(e << "f"_mst)); // d conflicts with f
    assert(!(e << "V"_mst) ||  (e << "f"_mst)); // V implies f
    assert(!(e << "K"_mst) ||  (e << "s"_mst)); // K implies s
    assert(!(e << "z"_mst) ||  (e << "m"_mst)); // z implies m
    return e;
}

Type CalcSimpleType(NodeType nodetype, Type x, Type y, Type z) {
    // Below is the per-nodetype logic for computing the expression types.
    // It heavily relies on Type's << operator (where "X << a_mst" means
    // "X has all properties listed in a").
    switch (nodetype) {
        case NodeType::PK: return "Konudemsx"_mst;
        case NodeType::PK_H: return "Knudemsx"_mst;
        case NodeType::OLDER: return "Bzfmx"_mst;
        case NodeType::AFTER: return "Bzfmx"_mst;
        case NodeType::SHA256: return "Bonudm"_mst;
        case NodeType::RIPEMD160: return "Bonudm"_mst;
        case NodeType::HASH256: return "Bonudm"_mst;
        case NodeType::HASH160: return "Bonudm"_mst;
        case NodeType::TRUE: return "Bzufmx"_mst;
        case NodeType::FALSE: return "Bzudemsx"_mst;
        case NodeType::WRAP_A: return
            "W"_mst.If(x << "B"_mst) | // W=B_x
            (x & "udfems"_mst) | // u=u_x, d=d_x, f=f_x, e=e_x, m=m_x, s=s_x
            "x"_mst; // x
        case NodeType::WRAP_S: return
            "W"_mst.If(x << "Bo"_mst) | // W=B_x*o_x
            (x & "udfemsx"_mst); // u=u_x, d=d_x, f=f_x, e=e_x, m=m_x, s=s_x, x=x_x
        case NodeType::WRAP_C: return
            "B"_mst.If(x << "K"_mst) | // B=K_x
             (x & "ondem"_mst) | // o=o_x, n=n_x, d=d_x, e=e_x, m=m_x
             "us"_mst; // u, s
        case NodeType::WRAP_D: return
            "B"_mst.If(x << "Vz"_mst) | // B=V_x*z_x
            "o"_mst.If(x << "z"_mst) | // o=z_x
            "e"_mst.If(x << "f"_mst) | // e=f_x
            (x & "ms"_mst) | // m=m_x, s=s_x
            "nudx"_mst; // n, u, d, x
        case NodeType::WRAP_V: return
            "V"_mst.If(x << "B"_mst) | // V=B_x
            (x & "zonms"_mst) | // z=z_x, o=o_x, n=n_x, m=m_x, s=s_x
            "fx"_mst; // f, x
        case NodeType::WRAP_J: return
            "B"_mst.If(x << "Bn"_mst) | // B=B_x*n_x
            "e"_mst.If(x << "f"_mst) | // e=f_x
            (x & "oums"_mst) | // o=o_x, u=u_x, m=m_x, s=s_x
            "ndx"_mst; // n, d, x
        case NodeType::WRAP_N: return
            (x & "Bzondfems"_mst) | // B=B_x, z=z_x, o=o_x, n=n_x, d=d_x, f=f_x, e=e_x, m=m_x, s=s_x
            "ux"_mst; // u, x
        case NodeType::AND_V: return
            (y & "KVB"_mst).If(x << "V"_mst) | // B=V_x*B_y, V=V_x*V_y, K=V_x*K_y
            (x & "n"_mst) | (y & "n"_mst).If(x << "z"_mst) | // n=n_x+z_x*n_y
            ((x | y) & "o"_mst).If((x | y) << "z"_mst) | // o=o_x*z_y+z_x*o_y
            (x & y & "dmz"_mst) | // d=d_x*d_y, m=m_x*m_y, z=z_x*z_y
            ((x | y) & "s"_mst) | // s=s_x+s_y
            (y & "ufx"_mst); // u=u_y, f=f_y, x=x_y
        case NodeType::AND_B: return
            (x & "B"_mst).If(y << "W"_mst) | // B=B_x*W_y
            ((x | y) & "o"_mst).If((x | y) << "z"_mst) | // o=o_x*z_y+z_x*o_y
            (x & "n"_mst) | (y & "n"_mst).If(x << "z"_mst) | // n=n_x+z_x*n_y
            (x & y & "e"_mst).If((x & y) << "s"_mst) | // e=e_x*e_y*s_x*s_y
            (x & y & "dfzm"_mst) | // d=d_x*d_y, f=f_x*f_y, z=z_x*z_y, m=m_x*m_y
            ((x | y) & "s"_mst) | // s=s_x+s_y
            "ux"_mst; // u, x
        case NodeType::OR_B: return
            "B"_mst.If(x << "Bd"_mst && y << "Wd"_mst) | // B=B_x*d_x*W_x*d_y
            ((x | y) & "o"_mst).If((x | y) << "z"_mst) | // o=o_x*z_y+z_x*o_y
            (x & y & "m"_mst).If((x | y) << "s"_mst && (x & y) << "e"_mst) | // m=m_x*m_y*e_x*e_y*(s_x+s_y)
            (x & y & "zse"_mst) | // z=z_x*z_y, s=s_x*s_y, e=e_x*e_y
            "dux"_mst; // d, u, x
        case NodeType::OR_D: return
            (y & "B"_mst).If(x << "Bdu"_mst) | // B=B_y*B_x*d_x*u_x
            (x & "o"_mst).If(y << "z"_mst) | // o=o_x*z_y
            (x & y & "m"_mst).If(x << "e"_mst && (x | y) << "s"_mst) | // m=m_x*m_y*e_x*(s_x+s_y)
            (x & y & "zes"_mst) | // z=z_x*z_y, e=e_x*e_y, s=s_x*s_y
            (y & "ufd"_mst) | // u=u_y, f=f_y, d=d_y
            "x"_mst; // x
        case NodeType::OR_C: return
            (y & "V"_mst).If(x << "Bdu"_mst) | // V=V_y*B_x*u_x*d_x
            (x & "o"_mst).If(y << "z"_mst) | // o=o_x*z_y
            (x & y & "m"_mst).If(x << "e"_mst && (x | y) << "s"_mst) | // m=m_x*m_y*e_x*(s_x*s_y)
            (x & y & "zs"_mst) | // z=z_x*z_y, s=s_x*s_y
            "fx"_mst; // f, x
        case NodeType::OR_I: return
            (x & y & "VBKufs"_mst) | // V=V_x*V_y, B=B_x*B_y, K=K_x*K_y, u=u_x*u_y, f=f_x*f_y, s=s_x*s_y
            "o"_mst.If((x & y) << "z"_mst) | // o=z_x*z_y
            ((x | y) & "e"_mst).If((x | y) << "f"_mst) | // e=e_x*f_y+f_x*e_y
            (x & y & "m"_mst).If((x | y) << "s"_mst) | // m=m_x*m_y*(s_x+s_y)
            ((x | y) & "d"_mst) | // d=d_x+d_y
            "x"_mst; // x
        case NodeType::ANDOR: return
            (y & z & "BKV"_mst).If(x << "Bdu"_mst) | // B=B_x*d_x*u_x*B_y*B_z, K=B_x*d_x*u_x*K_y*K_z, V=B_x*d_x*u_x*V_y*V_z
            (x & y & z & "z"_mst) | // z=z_x*z_y*z_z
            ((x | (y & z)) & "o"_mst).If((x | (y & z)) << "z"_mst) | // o=o_x*z_y*z_z+z_x+o_y*o_z
            (y & z & "fu"_mst) | // f=f_y*f_z, u=u_y*u_z
            (z & "d"_mst) | // d=d_x
            (x & z & "e"_mst).If(x << "s"_mst || y << "f"_mst) | // e=e_x*e_z*(s_x+s_y)
            (x & y & z & "m"_mst).If(x << "e"_mst && (x | y | z) << "s"_mst) | // m=m_x*m_y*m_z*e_x*(s_x+s_y+s_z)
            (z & (x | y) & "s"_mst) | // s=s_z*(s_x+s_y)
            "x"_mst; // x
        case NodeType::THRESH_M: return "Bnudems"_mst;
        case NodeType::THRESH: break;
    }
    assert(false);
    return ""_mst;
}

bool DecomposeScript(const CScript& script, std::vector<std::pair<opcodetype, std::vector<unsigned char>>>& out)
{
    out.clear();
    CScript::const_iterator it = script.begin(), itend = script.end();
    while (it != itend) {
        std::vector<unsigned char> push_data;
        opcodetype opcode;
        if (!script.GetOp(it, opcode, push_data)) {
            out.clear();
            return false;
        } else if (opcode >= OP_1 && opcode <= OP_16) {
            // Deal with OP_n (GetOp does not turn them into pushes).
            push_data.assign(1, CScript::DecodeOP_N(opcode));
        } else if (opcode == OP_CHECKSIGVERIFY) {
            // Decompose OP_CHECKSIGVERIFY into OP_CHECKSIG OP_VERIFY
            out.emplace_back(OP_CHECKSIG, std::vector<unsigned char>());
            opcode = OP_VERIFY;
        } else if (opcode == OP_CHECKMULTISIGVERIFY) {
            // Decompose OP_CHECKMULTISIGVERIFY into OP_CHECKMULTISIG OP_VERIFY
            out.emplace_back(OP_CHECKMULTISIG, std::vector<unsigned char>());
            opcode = OP_VERIFY;
        } else if (opcode == OP_EQUALVERIFY) {
            // Decompose OP_EQUALVERIFY into OP_EQUAL OP_VERIFY
            out.emplace_back(OP_EQUAL, std::vector<unsigned char>());
            opcode = OP_VERIFY;
        }
        out.emplace_back(opcode, std::move(push_data));
    }
    std::reverse(out.begin(), out.end());
    return true;
}

bool ParseScriptNumber(const std::pair<opcodetype, std::vector<unsigned char>>& in, int64_t& k) {
    if (in.first == OP_0) {
        k = 0;
        return true;
    }
    if (!in.second.empty()) {
        try {
            k = CScriptNum(in.second, true).GetInt64();
            return true;
        } catch(const scriptnum_error& error) {}
    }
    return false;
}

} // namespace internal
} // namespace miniscript

