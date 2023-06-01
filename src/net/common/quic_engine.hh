/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
#pragma once

// Seastar features.
#include <seastar/core/future.hh>       // seastar::future
#include <seastar/core/reactor.hh>      // seastar::engine()
#include <seastar/core/shared_ptr.hh>   // seastar::lw_shared_ptr
#include <seastar/net/socket_defs.hh>   // seastar::net::socket_address

// STD.
#include <unordered_map>
#include <variant>

namespace seastar::net {

// Central "unit" keeping track of all instances of QUIC sockets.
template<typename... QIs>
class quic_engine {
// Local definitions.
private:
    // Wrap pointers in a variant, not the types.
    // Pointers have the same size.
    using instance_type = std::variant<lw_shared_ptr<QIs>...>;
public:
    using type          = quic_engine<QIs...>;

// Fields.
private:
    std::unordered_map<socket_address, instance_type> _instances;

    // Do not make this inline. `quic_engine<QIs...>` is still
    // an incomplete type here, but we can declare it when no definition
    // is provided.
    //
    // "The declaration of a non-inline static data member in its class
    //  definition is not a definition and may be of an incomplete type
    //  other than cv void."
    //
    // --- Standard for C++17, section 12.2.3.2 [Static data members],
    // --- revise N4659.
    //
    // See also: https://en.cppreference.com/w/cpp/language/static
    static thread_local quic_engine<QIs...>           _engine;

// Constructors + the destructor.
private:
    quic_engine() = default;

    quic_engine(const quic_engine&) = delete;
    quic_engine& operator=(const quic_engine&) = delete;

    ~quic_engine() = default;

// Public methods.
public:
    template<typename T>
    static void register_instance(const socket_address& key, lw_shared_ptr<T> instance) {
        static_assert(std::disjunction_v<std::is_same<T, QIs>...>,
                "Invalid instance type");

        init_engine();
	if (_engine._instances.find(key) != _engine._instances.end()) {
		fmt::print("[QUIC_ENGINE]: clash between the keys of the map\n");
	}
        _engine._instances.emplace(key, instance);
    }

// Private methods.
private:
    static void init_engine() {
        thread_local bool cleanup_initialized = false;

        if (!cleanup_initialized) {
            engine().at_exit([] {
                future<> close_tasks = make_ready_future<>();
                for (auto& [_, instance] : _engine._instances) {
                    close_tasks = close_tasks.then([&instance = instance] {
                        return std::visit([] (auto ptr) {
                            return ptr->close();
                        }, instance);
                    });
                }
                return close_tasks;
            });
            cleanup_initialized = true;
        }
    }
};

template<typename... QIs>
inline thread_local quic_engine<QIs...> quic_engine<QIs...>::_engine{};

} // namespace seastar::net
