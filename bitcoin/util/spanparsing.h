// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_UTIL_SPANPARSING_H_
#define _BITCOIN_UTIL_SPANPARSING_H_ 1

#include <string>
#include <span.h>

/** Parse a constant. If successful, sp is updated to skip the constant and return true. */
bool Const(const std::string& str, Span<const char>& sp);

/** Parse a function call. If successful, sp is updated to be the function's argument(s). */
bool Func(const std::string& str, Span<const char>& sp);

/** Return the expression that sp begins with, and update sp to skip it. */
Span<const char> Expr(Span<const char>& sp);

#endif
