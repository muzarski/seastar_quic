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

#include "net/common/quic_common.hh"    // qlogger

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
    bool                                              _cleanup_initialized = false;

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

        auto& engine = quic_engine<QIs...>::get_singleton_instance();
        engine.init_engine();
        if (engine._instances.find(key) != engine._instances.end()) {
            fmt::print("[QUIC_ENGINE]: clash between the keys of the map\n");
        }
        engine._instances.emplace(key, instance);
    }

// Private methods.
private:
    static quic_engine<QIs...>& get_singleton_instance() {
        static thread_local quic_engine<QIs...> instance{};
        return instance;
    }

    void init_engine() {
        if (!_cleanup_initialized) {
            engine().at_exit([this] {
                qlogger.info("[quic_engine::at_exit] Closing {} quic instances.", _instances.size());
                future<> close_tasks = make_ready_future<>();
                for (auto& [_, instance] : _instances) {
                    close_tasks = close_tasks.then([&instance = instance] {
                        return std::visit([] (auto ptr) {
                            return ptr->stop();
                        }, instance);
                    });
                }
                return close_tasks.then([] () {
                    qlogger.info("[quic_engine::at_exit] Successfully closed quic instances.");
                });
            });
            _cleanup_initialized = true;
        }
    }
};

} // namespace seastar::net
