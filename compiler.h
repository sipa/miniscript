// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_SCRIPT_MINISCRIPT_COMPILER_H_
#define _BITCOIN_SCRIPT_MINISCRIPT_COMPILER_H_

#include <script/miniscript.h>

#include <string>

struct CompilerKey {
    std::string name;

};

struct CompilerContext {
    typedef CompilerKey Key;

    std::string ToString(const Key& key) const { return key.name; }

    template<typename I>
    bool FromString(I first, I last, Key& key) const { key.name = std::string(first, last); return true; }
};

extern const CompilerContext COMPILER_CTX;

bool Compile(const std::string& policy, miniscript::NodeRef<CompilerKey>& ret, double& avgcost);

std::string Expand(std::string str);
std::string Abbreviate(std::string str);

#endif
