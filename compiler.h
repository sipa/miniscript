// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_SCRIPT_MINISCRIPT_COMPILER_H_
#define _BITCOIN_SCRIPT_MINISCRIPT_COMPILER_H_

#include <script/miniscript.h>

#include <string>

struct CompilerContext {
    typedef std::string Key;

    std::optional<std::string> ToString(const Key& key) const { return key; }

    template<typename I>
    std::optional<Key> FromString(I first, I last) const {
        if (std::distance(first, last) == 0 || std::distance(first, last) > 17) return {};
        return std::string(first, last);
    }

    std::vector<unsigned char> ToPKBytes(const Key& key) const {
        std::vector<unsigned char> ret{2, 'P', 'K', 'b'};
        ret.resize(33, 0);
        std::copy(key.begin(), key.end(), ret.begin() + 4);
        return ret;
    }

    std::vector<unsigned char> ToPKHBytes(const Key& key) const {
        std::vector<unsigned char> ret{'P', 'K', 'h'};
        ret.resize(20, 0);
        std::copy(key.begin(), key.end(), ret.begin() + 3);
        return ret;
    }

    bool KeyCompare(const Key& a, const Key& b) const {
        return a < b;
    }
};

extern const CompilerContext COMPILER_CTX;

bool Compile(const std::string& policy, miniscript::NodeRef<CompilerContext::Key>& ret, double& avgcost);

std::string Expand(std::string str);
std::string Abbreviate(std::string str);

std::string Disassemble(const CScript& script);

#endif
