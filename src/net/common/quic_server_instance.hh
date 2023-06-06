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
#include "quic_common.hh"
#include "quiche_config.hh"
#include "udp_manager.hh"

// Seastar features.
#include <seastar/core/future.hh>           // seastar::future
#include <seastar/core/gate.hh>             // seastar::gate
#include <seastar/core/loop.hh>             // seastar::parallel_for_each
#include <seastar/core/queue.hh>            // seastar::queue
#include <seastar/core/shared_future.hh>    // seastar::shared_{future, promise}
#include <seastar/core/shared_ptr.hh>       // seastar::lw_shared_ptr
#include <seastar/core/temporary_buffer.hh> // seastar::temporary_buffer
#include <seastar/core/weak_ptr.hh>         // seastar::weakly_referencable
#include <seastar/net/api.hh>               // seastar::net::udp_datagram
#include <seastar/net/socket_defs.hh>       // seastar::net::socket_address
#include <seastar/net/quic.hh>              // seastar::net::quic_connection_config

// Debug features.
#include <fmt/core.h>   // For development purposes, ditch this later on.

// Third-party API.
#include <quiche.h>

// STD.
#include <algorithm>
#include <chrono>           // Pacing
#include <cstring>          // std::memcpy, etc.
#include <string>           // TODO: Probably to be ditched.
#include <string_view>
#include <exception>
#include <unordered_map>
#include <vector>


namespace seastar::net {

// TODO: Think if some classes/structs should/should not be marked as `final`.


//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//@|=================================|@
//@|.................................|@
//@|.................................|@
//@|.......... Declaration ..........|@
//@|.................................|@
//@|.................................|@
//@|=================================|@
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@



// Servers are parameterized by the type of connections they hold,
// e.g. whether it's a HTTP/3 server or a "raw" QUIC server.
//
// The connection type is a template parameterized by
// the QUIC socket instance that holds it, i.e.
// this or some other instance class.
//
// Refer to the diagram above to get a more illustrative
// and high-level view on the design.
template<template<typename> typename ConnectionT>
class quic_server_instance : public weakly_referencable<quic_server_instance<ConnectionT>> {
// Local definitions.
public:
    using connection_type = ConnectionT<quic_server_instance<ConnectionT>>;
    using type            = quic_server_instance<ConnectionT>;

// Local constants.
private:
    // TODO: Check the comments left in the function `quic_retry`.
    // Right now, tokens aren't used properly and passing `socket_address::length()`
    // to quiche's functions causes validation of them return false. Investigate it.
    constexpr static size_t MAX_TOKEN_SIZE =
            sizeof("quiche") - 1 + sizeof(::sockaddr_storage) + MAX_QUIC_CONNECTION_ID_LENGTH;

// Local structures.
private:
    template<size_t Length>
    struct cid_template {
        constexpr static size_t CID_MAX_LENGTH = Length;

        uint8_t data[Length];
        size_t  length = sizeof(data);
    };

    template<size_t TokenSize>
    struct header_token_template {
        constexpr static size_t HEADER_TOKEN_MAX_SIZE = TokenSize;

        uint8_t data[TokenSize];
        size_t  size = sizeof(data);
    };

    using cid          = cid_template<MAX_QUIC_CONNECTION_ID_LENGTH>;
    using header_token = header_token_template<MAX_TOKEN_SIZE>;

    struct quic_header_info {
        uint8_t  type;
        uint32_t version;

        cid scid;
        cid dcid;
        cid odcid;

        header_token token;
    };

    class marker {
    private:
        bool _marked = false;

    public:
        constexpr void mark() noexcept { _marked = true; }
        constexpr operator bool() const noexcept { return _marked; }
    };

// Fields.
protected:
    quiche_configuration                                                   _quiche_configuration;
    quic_udp_channel_manager                                               _channel_manager;
    std::vector<quic_byte_type>                                            _buffer;
    std::unordered_map<quic_connection_id, lw_shared_ptr<connection_type>> _connections;
    queue<lw_shared_ptr<connection_type>>                                  _waiting_queue;
    future<>                                                               _send_queue;
    gate                                                                   _service_gate;
    std::optional<shared_future<>>                                         _stopped;

// Constructors and the destructor.
public:
    explicit quic_server_instance(const socket_address& sa, const std::string_view cert,
            const std::string_view key, const quic_connection_config& quic_config,
            const size_t queue_length)
    : _quiche_configuration(cert, key, quic_config)
    , _channel_manager(sa)
    , _buffer(MAX_DATAGRAM_SIZE)
    , _waiting_queue(queue_length)
    , _send_queue(make_ready_future<>())
    , _service_gate() {}

    explicit quic_server_instance(const std::string_view cert, const std::string_view key,
            const quic_connection_config& quic_config, const size_t queue_length)
    : _quiche_configuration(cert, key, quic_config)
    , _channel_manager()
    , _buffer(MAX_DATAGRAM_SIZE)
    , _waiting_queue(queue_length)
    , _send_queue(make_ready_future<>())
    , _service_gate() {}

    ~quic_server_instance() = default;

// Public methods.
public:
    future<> send(send_payload&& payload);
    future<> handle_connection_aborting(const quic_connection_id& cid);

    future<lw_shared_ptr<connection_type>> accept();
    void abort_accept() noexcept;

    [[nodiscard]] connection_data connect(const socket_address& sa);
    [[nodiscard]] socket_address local_address() const {
        return _channel_manager.local_address();
    }
    void register_connection(lw_shared_ptr<connection_type> conn);
    void init();
    // TODO: Ditch this.
    [[nodiscard]] std::string name() const;
    future<> stop();
    [[nodiscard]] gate& qgate() noexcept {
        return _service_gate;
    }

// Private methods.
private:
    future<> service_loop();
    future<> handle_datagram(udp_datagram&& datagram);
    future<> handle_post_hs_connection(lw_shared_ptr<connection_type> conn, udp_datagram&& datagram);
    // TODO: Check if we cannot provide const references here instead.
    future<> handle_pre_hs_connection(quic_header_info& header_info, udp_datagram&& datagram,
            const quic_connection_id& key);
    future<> negotiate_version(const quic_header_info& header_info, udp_datagram&& datagram);
    future<> quic_retry(const quic_header_info& header_info, udp_datagram&& datagram);
    quic_connection_id generate_new_cid();


    static header_token mint_token(const quic_header_info& header_info, const ::sockaddr_storage* addr,
            ::socklen_t addr_len);
    // TODO: Change this function to something proper, less C-like.
    static bool validate_token(const uint8_t* token, size_t token_len, const ::sockaddr_storage* addr,
            ::socklen_t addr_len, uint8_t* odcid, size_t* odcid_len);
};



//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//@|=================================|@
//@|.................................|@
//@|.................................|@
//@|.......... Definitions ..........|@
//@|.................................|@
//@|.................................|@
//@|=================================|@
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@



template<template<typename> typename CT>
future<> quic_server_instance<CT>::send(send_payload&& payload) {
    return _channel_manager.send(std::move(payload));
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::handle_connection_aborting(const quic_connection_id& cid) {
    if (!_stopped) {
        _connections.erase(cid);
    }
    return make_ready_future<>();
}

template<template<typename> typename CT>
future<lw_shared_ptr<typename quic_server_instance<CT>::connection_type>>
quic_server_instance<CT>::accept() {
    return _waiting_queue.not_empty().then([this] {
        return make_ready_future<lw_shared_ptr<connection_type>>(_waiting_queue.pop());
    });
}

template<template<typename> typename CT>
void quic_server_instance<CT>::abort_accept() noexcept {
    _waiting_queue.abort(std::make_exception_ptr(
            std::system_error(ECONNABORTED, std::system_category())));
}

// TODO: To ditch? Servers do NOT connect.
template<template<typename> typename CT>
[[nodiscard]] connection_data quic_server_instance<CT>::connect(const socket_address& sa) {
    throw std::runtime_error("Internal API error - bad state.");
}

template<template<typename> typename CT>
void quic_server_instance<CT>::register_connection(lw_shared_ptr<connection_type> conn) {
    _connections[conn->cid()] = conn;
}

template<template<typename> typename CT>
void quic_server_instance<CT>::init() {
    (void) try_with_gate(_service_gate, [this] () {
        return _channel_manager.run();
    }).handle_exception_type([] (const gate_closed_exception& e) {
    }).handle_exception([] (const std::exception_ptr& e) {
        qlogger.warn("[quic_server_instance::init]: udp channel manager error: {}", e);
    });

    (void) try_with_gate(_service_gate, [this] () {
        return service_loop().handle_exception_type([] (const quic_aborted_exception& e) {});
    }).handle_exception_type([] (const gate_closed_exception& e) {
    }).handle_exception([] (const std::exception_ptr& e) {
        qlogger.warn("[quic_client_instance::init]: service_loop error {}", e);
    });
}

// TODO: Ditch this.
template<template<typename> typename CT>
[[nodiscard]] std::string quic_server_instance<CT>::name() const {
    return "server";
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::stop() {
    if (_stopped) {
        return _stopped->get_future();
    }

    shared_promise<> stopped;
    _stopped.emplace(stopped.get_shared_future());

    return parallel_for_each(_connections, [] (auto& c) {
        auto& [_, conn] = c;
        return conn->abort();
    }).then([this, stopped = std::move(stopped)] () mutable {
        _channel_manager.abort_read_queue();

        qlogger.info("Scheduled udp channel flush");
        return _channel_manager.flush_write_queue().then([this] {
            qlogger.info("After flush.");
            _channel_manager.abort_write_queue();
            return _service_gate.close().then([] () {
                qlogger.info("service gate closed");
            });
        }).then([stopped = std::move(stopped)] () mutable {
            stopped.set_value();
            return make_ready_future<>();
        });
    });
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::service_loop() {
    return keep_doing([this] () {
        return _channel_manager.read().then([this] (udp_datagram datagram) {
            return handle_datagram(std::move(datagram));
        });
    });
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::handle_datagram(udp_datagram&& datagram) {
    quic_header_info header_info;

    const auto* fa = datagram.get_data().fragment_array();
    std::memcpy(_buffer.data(), fa->base, fa->size);

    quic_connection_id key;

    const auto parse_header_result = quiche_header_info(
            reinterpret_cast<uint8_t*>(_buffer.data()),
            fa->size,
            sizeof(key.cid),
            &header_info.version,
            &header_info.type,
            header_info.scid.data,
            &header_info.scid.length,
            header_info.dcid.data,
            &header_info.dcid.length,
            header_info.token.data,
            &header_info.token.size
    );

    if (parse_header_result < 0) {
        // fmt::print(stderr, "Failed to parse a QUIC header: {}\n", parse_header_result);
        return make_ready_future<>();
    }

    std::memcpy(key.cid, header_info.dcid.data, header_info.dcid.length);

    auto it = _connections.find(key);
    if (it == _connections.end()) {
        return handle_pre_hs_connection(header_info, std::move(datagram), key);
    } else {
        return handle_post_hs_connection(it->second, std::move(datagram));
    }
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::handle_post_hs_connection(lw_shared_ptr<connection_type> conn, udp_datagram&& datagram) {
    conn->receive(std::move(datagram));
    conn->send_outstanding_data_in_streams_if_possible();
    return conn->quic_flush();
}

// TODO: Check if we cannot provide const references here instead.
template<template<typename> typename CT>
future<> quic_server_instance<CT>::handle_pre_hs_connection(quic_header_info& header_info,
        udp_datagram&& datagram, const quic_connection_id& key) {
    if (!quiche_version_is_supported(header_info.version)) {
        // fmt::print("Negotiating the version...\n");
        return negotiate_version(header_info, std::move(datagram));
    }

    if (header_info.token.size == 0) {
        // fmt::print("quic_retry...\n");
        return quic_retry(header_info, std::move(datagram));
    }

    // TODO: Refactor this
    const auto addr = datagram.get_src().as_posix_sockaddr();
    const auto* peer_addr = reinterpret_cast<const ::sockaddr_storage*>(&addr);
    const auto peer_addr_len = sizeof(addr);

    const auto local_addr = datagram.get_dst().as_posix_sockaddr();
    const auto local_addr_len = sizeof(local_addr);

    const bool validated_token = validate_token(
            header_info.token.data,
            header_info.token.size,
            peer_addr,
            peer_addr_len,
            reinterpret_cast<uint8_t*>(header_info.odcid.data),
            &header_info.odcid.length
    );

    if (!validated_token) {
        fmt::print(stderr, "Invalid address validation token.\n");
        return make_ready_future<>();
    }

    quiche_conn* connection = quiche_accept(
            header_info.dcid.data,
            header_info.dcid.length,
            header_info.odcid.data,
            header_info.odcid.length,
            &local_addr,
            local_addr_len,
            &addr,
            peer_addr_len,
            _quiche_configuration.get_underlying_config()
    );

    if (connection == nullptr) {
        // fmt::print(stderr, "Creating a connection has failed.\n");
        return make_ready_future<>();
    }

    auto conn = make_lw_shared<connection_type>(connection, this->weak_from_this(),
            datagram.get_src(), key);
    _waiting_queue.push(lw_shared_ptr(conn));
    conn->init(); // TODO: to be checked
    return handle_post_hs_connection(conn, std::move(datagram));
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::negotiate_version(const quic_header_info& header_info, udp_datagram&& datagram) {
    const auto written = quiche_negotiate_version(
            header_info.scid.data,
            header_info.scid.length,
            header_info.dcid.data,
            header_info.dcid.length,
            reinterpret_cast<uint8_t*>(_buffer.data()),
            _buffer.size()
    );

    if (written < 0) {
        // fmt::print(stderr, "negotiate_version: failed to created a packet. Return value: {}\n", written);
        return make_ready_future<>();
    }

    temporary_buffer<quic_byte_type> tb{reinterpret_cast<quic_byte_type*>(_buffer.data()), static_cast<size_t>(written)};
    send_payload payload{std::move(tb), datagram.get_src()};

    return _channel_manager.send(std::move(payload));
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::quic_retry(const quic_header_info& header_info, udp_datagram&& datagram) {
    const auto addr = datagram.get_src().as_posix_sockaddr();
    const auto* peer_addr = reinterpret_cast<const ::sockaddr_storage*>(&addr);
    // TODO: Changing this to `datagram.get_src().length()`, which, to my understanding, should be
    // the right thing to do, causes validating the token return false later on. I think we should review
    // how exactly we use sizes of the address structs.
    const auto addr_len = sizeof(addr);

    const auto token = mint_token(header_info, peer_addr, addr_len);
    quic_connection_id new_cid = generate_new_cid();

    const auto written = quiche_retry(
            header_info.scid.data,
            header_info.scid.length,
            header_info.dcid.data,
            header_info.dcid.length,
            new_cid.cid,
            sizeof(new_cid.cid),
            token.data,
            token.size,
            header_info.version,
            reinterpret_cast<uint8_t*>(_buffer.data()),
            _buffer.size()
    );

    if (written < 0) {
        fmt::print(stderr, "Failed to create a retry QUIC packet. Return value: {}\n", written);
        return make_ready_future<>();
    }

    temporary_buffer<quic_byte_type> tb{reinterpret_cast<quic_byte_type*>(_buffer.data()), static_cast<size_t>(written)};
    send_payload payload(std::move(tb), datagram.get_src());

    return _channel_manager.send(std::move(payload));
}

template<template<typename> typename CT>
quic_connection_id quic_server_instance<CT>::generate_new_cid() {
    quic_connection_id result;

    do {
        result = quic_connection_id::generate();
    } while (_connections.find(result) != _connections.end());

    return result;
}


/// STATIC

template<template<typename> typename CT>
typename quic_server_instance<CT>::header_token quic_server_instance<CT>::mint_token(
            const quic_header_info& header_info, const ::sockaddr_storage* addr,
            ::socklen_t addr_len)
{
    header_token result;

    std::memcpy(result.data, "quiche", sizeof("quiche") - 1);
    std::memcpy(result.data + sizeof("quiche") - 1, addr, addr_len);
    std::memcpy(result.data + sizeof("quiche") - 1 + addr_len, header_info.dcid.data, header_info.dcid.length);

    result.size = sizeof("quiche") - 1 + addr_len + header_info.dcid.length;

    return result;
}

// TODO: Change this function to something proper, less C-like.
template<template<typename> typename CT>
bool quic_server_instance<CT>::validate_token(const uint8_t* token, size_t token_len, const ::sockaddr_storage* addr,
        ::socklen_t addr_len, uint8_t* odcid, size_t* odcid_len)
{
    if (token_len < sizeof("quiche") - 1 || std::memcmp(token, "quiche", sizeof("quiche") - 1) != 0) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if (token_len < addr_len || std::memcmp(token, addr, addr_len) != 0) {
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
        return false;
    }

    std::memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}


} // namespace seastar::net
