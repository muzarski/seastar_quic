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

// Other private things.
#include "udp_manager.hh"
#include "quic_common.hh"
#include "quiche_config.hh"

// Seastar features.
#include <seastar/core/future.hh>           // seastar::future
#include <seastar/core/gate.hh>             // seastar::gate
#include <seastar/core/shared_future.hh>    // seastar::shared_{future, promise}
#include <seastar/core/shared_ptr.hh>       // seastar::lw_shared_ptr
#include <seastar/core/weak_ptr.hh>         // seastar::weakly_referencable
#include <seastar/net/socket_defs.hh>       // seastar::net::socket_address

// STD.
#include <string> // TODO: Probably to be ditched.

namespace seastar::net {


//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//@|=================================|@
//@|.................................|@
//@|.................................|@
//@|.......... Declaration ..........|@
//@|.................................|@
//@|.................................|@
//@|=================================|@
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@



// Despite the fact that clients, unlike servers, cannot correspond
// to any type connection other than the "raw" QUIC one, we make this
// class a template for preserving a consistent code style.
//
// The connection type is a template parameterized by
// the QUIC socket instance that holds it, i.e.
// this or some other instance class.
template<template<typename> typename ConnectionT>
class quic_client_instance : public weakly_referencable<quic_client_instance<ConnectionT>> {
// Local definitions.
public:
    using connection_type = ConnectionT<quic_client_instance<ConnectionT>>;
    using type            = quic_client_instance<ConnectionT>;

// Fields.
protected:
    quic_udp_channel_manager       _channel_manager;
    quiche_configuration           _quiche_configuration;
    lw_shared_ptr<connection_type> _connection;
    gate                           _service_gate;
    std::optional<shared_future<>> _stopped;

// Constructors and the destructor.
public:
    explicit quic_client_instance(const quic_connection_config& quic_config)
    : _channel_manager()
    , _quiche_configuration(quic_config)
    , _connection()
    , _service_gate()
    , _stopped(std::nullopt) {}

    ~quic_client_instance() = default;

// Public methods.
public:
    future<> send(send_payload&& payload);
    future<> handle_connection_aborting(const quic_connection_id& cid);
    [[nodiscard]] connection_data connect(const socket_address& sa);
    void register_connection(lw_shared_ptr<connection_type> conn);
    void init();
    future<> close();
    [[nodiscard]] socket_address local_address() const {
        return _channel_manager.local_address();
    }
    [[nodiscard]] gate& qgate() noexcept {
        return _service_gate;
    }
    future<> stop();

// Private methods.
private:
    future<> receive_loop();
    future<> receive();
    future<> abort();
};



//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//@|=================================|@
//@|.................................|@
//@|.................................|@
//@|.......... Definition ...........|@
//@|.................................|@
//@|.................................|@
//@|=================================|@
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@



template<template<typename> typename CT>
future<> quic_client_instance<CT>::send(send_payload&& payload) {
    return _channel_manager.send(std::move(payload));
}

template<template<typename> typename CT>
future<> quic_client_instance<CT>::stop() {
    return _connection->abort().then([this] {
        return _stopped->get_future();
    });
}

template<template<typename> typename CT>
future<> quic_client_instance<CT>::abort() {
    if (_stopped) {
        return make_ready_future<>();
    }

    shared_promise<> stopped;
    _stopped.emplace(stopped.get_shared_future());

    _channel_manager.abort_read_queue();

    qlogger.info("Scheduled udp channel flush");
    return _channel_manager.flush_write_queue().then([this] {
        qlogger.info("After flush.");
        _channel_manager.abort_write_queue();
        return _service_gate.close().then([] {
            qlogger.info("service gate closed");
        });
    }).then([stopped = std::move(stopped)] () mutable {
        stopped.set_value();
    });
}

template<template<typename> typename CT>
future<> quic_client_instance<CT>::handle_connection_aborting([[maybe_unused]] const quic_connection_id& cid) {
    // std::cout << "quic_client_instance::abort()" << std::endl;
    return abort();
}

template<template<typename> typename CT>
[[nodiscard]] connection_data quic_client_instance<CT>::connect(const socket_address& sa) {
    const socket_address la = _channel_manager.local_address();
    quic_connection_id cid = quic_connection_id::generate();

    auto* connection_ptr = quiche_connect(
            nullptr,    // TODO: Decide on the hostname
            cid.cid,
            sizeof(cid.cid),
            &la.as_posix_sockaddr(),
            la.length(),
            &sa.as_posix_sockaddr(),
            sa.length(),
            _quiche_configuration.get_underlying_config()
    );

    if (!connection_ptr) {
        throw std::runtime_error("Creating a QUIC connection has failed.");
    }

    return {.conn = connection_ptr, .id = cid, .pa = sa};
}

template<template<typename> typename CT>
void quic_client_instance<CT>::register_connection(lw_shared_ptr<connection_type> conn) {
    _connection = conn;
}

template<template<typename> typename CT>
void quic_client_instance<CT>::init() {
    // Start udp channel under the hood.
    (void) try_with_gate(_service_gate, [this] () {
        return _channel_manager.run();
    }).handle_exception_type([] (const gate_closed_exception& e) {
    }).handle_exception([] (const std::exception_ptr& e) {
        qlogger.warn("[quic_client_instance::init]: udp channel manager error: {}", e);
    });

    // Run receive fiber in the background.
    (void) try_with_gate(_service_gate, [this] () {
        return receive_loop().handle_exception_type([] (const quic_aborted_exception& e) {});
    }).handle_exception_type([] (const gate_closed_exception& e) {
    }).handle_exception([] (const std::exception_ptr& e) {
        qlogger.warn("[quic_client_instance::init]: receive_loop error {}", e);
    });
}

template<template<typename> typename CT>
future<> quic_client_instance<CT>::close() {
    return make_ready_future<>();
}

template<template<typename> typename CT>
future<> quic_client_instance<CT>::receive_loop() {
    return keep_doing([this] { return receive(); });
}

template<template<typename> typename CT>
future<> quic_client_instance<CT>::receive() {
    return _channel_manager.read().then([this] (udp_datagram&& datagram) {
        _connection->receive(std::move(datagram));
        _connection->send_outstanding_data_in_streams_if_possible();
        return _connection->quic_flush();
    });
}

} // namespace::net
