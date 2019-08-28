// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_UTIL_VECTOR_H_
#define _BITCOIN_UTIL_VECTOR_H_ 1

#include <vector>
#include <utility>

namespace vector {
namespace internal {

/** Compute the number of arguments passed. */
inline constexpr unsigned NumArgs() { return 0; }
template<typename Arg, typename... Args>
inline constexpr unsigned NumArgs(Arg&&, Args&&... args) { return 1 + NumArgs(std::forward<Args>(args)...); }

/** Push back multiple elements to a container. */
template<typename V>
inline void PushBackMany(V& vec) {}
template<typename V, typename Arg, typename... Args>
inline void PushBackMany(V& vec, Arg&& arg, Args&&... args)
{
    vec.push_back(std::forward<Arg>(arg));
    PushBackMany(vec, std::forward<Args>(args)...);
}

} // namespace internal
} // namespace vector

/** Construct a vector with the specified elements.
 *
 * This is preferable over the list initializing constructor of std::vector:
 * - It automatically infers the element type of the vector.
 * - If arguments are rvalue references, they will be moved into the vector
 *   (list initialization always copies).
 *
 * The first argument is used to determine the vector's element type. The
 * other arguments must be convertible to that type.
 */
template<typename Arg, typename... Args>
inline std::vector<typename std::remove_cv<typename std::remove_reference<Arg>::type>::type> Vector(Arg&& arg, Args&&... args)
{
    using namespace vector::internal;
    std::vector<typename std::remove_cv<typename std::remove_reference<Arg>::type>::type> ret;
    ret.reserve(1 + NumArgs(std::forward<Args>(args)...));
    ret.push_back(std::forward<Arg>(arg));
    PushBackMany(ret, std::forward<Args>(args)...);
    return ret;
}

/** Concatenate two vectors, moving elements. */
template<typename V>
inline V Cat(V v1, V&& v2)
{
    v1.reserve(v1.size() + v2.size());
    for (auto& arg : v2) {
        v1.push_back(std::move(arg));
    }
    return v1;
}

/** Concatenate two vectors. */
template<typename V>
inline V Cat(V v1, const V& v2)
{
    v1.reserve(v1.size() + v2.size());
    for (const auto& arg : v2) {
        v1.push_back(arg);
    }
    return v1;
}

#endif
