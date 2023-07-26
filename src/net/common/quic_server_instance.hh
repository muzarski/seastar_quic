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
#include <seastar/core/byteorder.hh>        // seastar::{write_be, read_be}
#include <seastar/core/future.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/loop.hh>             // seastar::parallel_for_each
#include <seastar/core/queue.hh>
#include <seastar/core/shared_future.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/core/weak_ptr.hh>         // seastar::weakly_referencable
#include <seastar/net/api.hh>               // seastar::net::udp_datagram
#include <seastar/net/inet_address.hh>
#include <seastar/net/ipv4_address.hh>
#include <seastar/net/ipv6_address.hh>
#include <seastar/net/socket_defs.hh>       // seastar::net::socket_address
#include <seastar/net/quic.hh>              // seastar::net::quic_connection_config

// Third-party API.
#include <quiche.h>

// STD.
#include <algorithm>
#include <chrono>           // Pacing, random seed.
#include <cstring>          // std::memcpy, etc.
#include <exception>
#include <optional>
#include <random>           // Generating tokens.
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <vector>


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


struct invalid_address : std::exception {
    const char* what() const noexcept {
        return "The passed address is unspecified or invalid.";
    }
};

struct invalid_cid : std::exception {
    const char* what() const noexcept {
        return "The passed connection ID is invalid.";
    }
};

struct invalid_token : std::exception {
    const char* what() const noexcept {
        return "The passed token is invalid.";
    }
};

struct quic_dcid : public quic_connection_id {
    constexpr static size_t MAX_DCID_LENGTH = MAX_QUIC_CONNECTION_ID_LENGTH;
    size_t size = quic_dcid::MAX_DCID_LENGTH;
};

struct header_token {
public:
    using version_type = char;
    constexpr static size_t VERSION_SIZE = sizeof(version_type);
    constexpr static size_t IP_SIZE = ipv6_address::size();
    constexpr static size_t PORT_SIZE = sizeof(::in_port_t);
    constexpr static size_t ENTROPY_SIZE = 16;
private:
    constexpr static size_t VERSION_OFFSET = 0;
    constexpr static size_t IP_OFFSET = VERSION_SIZE;
    constexpr static size_t PORT_OFFSET = IP_OFFSET + IP_SIZE;
    constexpr static size_t ENTROPY_OFFSET = PORT_OFFSET + PORT_SIZE;
    constexpr static size_t DCID_OFFSET = ENTROPY_OFFSET + ENTROPY_SIZE;

    constexpr static size_t TOKEN_SIZE = VERSION_SIZE + IP_SIZE + PORT_SIZE + ENTROPY_SIZE + quic_dcid::MAX_DCID_LENGTH;

public:
    char   bytes[TOKEN_SIZE];
    size_t length = sizeof(bytes);

public:
    inet_address::family ip_version() const {
        // TODO: Change this to std::bit_cast when C++20 is fully supported.
        //
        // Right now we're forced to use `std::memcpy` to avoid undefined behavior
        // related to unaligned access. Do NOT change this to a "raw" `reinterpret_cast`.
        version_type version;
        std::memcpy(&version, bytes + VERSION_OFFSET, sizeof(version));
        switch (version) {
            case 4: return inet_address::family::INET;
            case 6: return inet_address::family::INET6;
            default: throw invalid_token{};
        }
    }

    inet_address ip_address() const {
        switch (ip_version()) {
            case inet_address::family::INET:
                return ipv4_address::read(bytes + IP_OFFSET);
            case inet_address::family::INET6:
                return ipv6_address::read(bytes + IP_OFFSET);
        }
    }

    ::in_port_t port() const noexcept {
        // TODO: Change this to std::bit_cast when C++20 is fully supported.
        //
        // Right now we're forced to use `std::memcpy` to avoid undefined behavior
        // related to unaligned access. Do NOT change this to a "raw" `reinterpret_cast`.
        ::in_port_t result;
        std::memcpy(&result, bytes + PORT_OFFSET, sizeof(result));
        return result;
    }

    const uint8_t* entropy_data() const noexcept {
        return reinterpret_cast<const uint8_t*>(bytes + ENTROPY_OFFSET);
    }
    uint8_t* entropy_data() noexcept {
        return reinterpret_cast<uint8_t*>(bytes + ENTROPY_OFFSET);
    }

    quic_dcid dcid() const noexcept {
        // TODO: Change this to std::bit_cast when C++20 is fully supported.
        //
        // Right now we're forced to use `std::memcpy` to avoid undefined behavior
        // related to unaligned access. Do NOT change this to a "raw" `reinterpret_cast`.
        quic_dcid result;
        std::memcpy(&result.cid, bytes + DCID_OFFSET, quic_dcid::MAX_DCID_LENGTH);
        result.size = size() - DCID_OFFSET;
        return result;
    }

    // Perhaps unaligned.
    const uint8_t* cid_data() const noexcept {
        return reinterpret_cast<const uint8_t*>(bytes + DCID_OFFSET);
    }
    // Perhaps unaligned.
    uint8_t* cid_data() noexcept {
        return reinterpret_cast<uint8_t*>(bytes + DCID_OFFSET);
    }

    const uint8_t* data() const noexcept {
        return reinterpret_cast<const uint8_t*>(bytes);
    }
    uint8_t* data() noexcept {
        return reinterpret_cast<uint8_t*>(bytes);
    }
    const size_t size() const noexcept {
        return length;
    }

public:
    static header_token mint_token(const socket_address& sa, const std::string_view dcid) {
        // In QUIC version 1, connection IDs cannot be longer than 20 bytes.
        //
        // It is recommended that servers be able read longer connection IDs to
        // support other QUIC versions. That's a TODO.
        //
        // See RFC 9000, section 17.2 for more information.
        if (dcid.length() > quic_dcid::MAX_DCID_LENGTH) {
            throw invalid_cid{};
        }

        header_token result;
        char* dst = result.bytes;

        encode_address(dst, sa);
        generate_random_number(dst, ENTROPY_SIZE);

        std::memcpy(dst, dcid.data(), dcid.length());
        
        result.length = DCID_OFFSET + dcid.length();
        return result;
    }

    static bool validate_address(const header_token& token, const socket_address& sa) {
        char tmp[ENTROPY_OFFSET];
        char* dst = tmp;

        encode_address(dst, sa);

        return std::memcmp(tmp, token.bytes, sizeof(tmp)) == 0;
    }

private:
    static void encode_version(char*& dst, version_type version) noexcept {
        produce_be(dst, version);
    }

    static void encode_ipv4_addr(char*& dst, const ipv4_address& sa) noexcept {
        constexpr size_t IP_ZERO_PADDING_SIZE = IP_SIZE - ipv4_address::size(); 
        sa.produce(dst);
        std::memset(dst, 0, IP_ZERO_PADDING_SIZE);
        dst += IP_ZERO_PADDING_SIZE;
    }

    static void encode_ipv6_addr(char*& dst, const ipv6_address& sa) noexcept {
        sa.produce(dst);
    }

    static void encode_port(char*& dst, uint16_t port) noexcept {
        produce_be(dst, port);
    }

    static void encode_address(char*& dst, const socket_address& sa) {
        if (sa.addr().is_ipv4()) {
            encode_version(dst, 4);
            encode_ipv4_addr(dst, sa.addr().as_ipv4_address());
        } else if (sa.addr().is_ipv6()) {
            encode_version(dst, 6);
            encode_ipv6_addr(dst, sa.addr().as_ipv6_address());
        } else {
            throw invalid_address{};
        }

        encode_port(dst, sa.port());
    }

    static void generate_random_number(char*& dst, size_t width) {
        static thread_local std::mt19937_64 mersenne64(
                std::chrono::system_clock::now().time_since_epoch().count());
        
        while (width) {
            const auto random_number = mersenne64();
            const auto len = std::min(sizeof(random_number), width);

            std::memcpy(dst, &random_number, len);
            dst += len;
            width -= len;
        }
    }
};


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

// Local structures.
private:
    template<size_t Length>
    struct cid_template {
        constexpr static size_t CID_MAX_LENGTH = Length;

        uint8_t data[Length];
        size_t  length = sizeof(data);
    };

    using cid = cid_template<MAX_QUIC_CONNECTION_ID_LENGTH>;

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
    std::unordered_map<socket_address, header_token>                       _address_tokens;
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
    future<> handle_pre_hs_connection(const quic_header_info& header_info, udp_datagram&& datagram,
            const quic_connection_id& key);
    future<> negotiate_version(const quic_header_info& header_info, udp_datagram&& datagram);
    future<> quic_retry(const quic_header_info& header_info, udp_datagram&& datagram);
    quic_connection_id generate_new_cid();
    std::optional<quic_dcid> validate_token(const header_token& token, const socket_address& sa);
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
    qlogger.info("Sending {} bytes", payload.buffer.size());
    return _channel_manager.send(std::move(payload));
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::handle_connection_aborting(const quic_connection_id& cid) {
    if (!_stopped) {
        //_connections.erase(cid);
        // std::cout << "quic_server_instance: removed connection from the map" << std::endl;
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
    (void) try_with_gate(_service_gate, [this] {
        return _channel_manager.run();
    }).handle_exception_type([] (const gate_closed_exception& e) {
    }).handle_exception([] (const std::exception_ptr& e) {
        qlogger.warn("[quic_server_instance::init]: UDP channel manager error: {}", e);
    });

    (void) try_with_gate(_service_gate, [this] {
        return service_loop().handle_exception_type([] (const quic_aborted_exception& e) {});
    }).handle_exception_type([] (const gate_closed_exception& e) {
    }).handle_exception([] (const std::exception_ptr& e) {
        qlogger.warn("[quic_client_instance::init]: service_loop error {}", e);
    });
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

        return _channel_manager.flush_write_queue().then([this] {
            _channel_manager.abort_write_queue();
            return _service_gate.close();
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
            qlogger.info("Received {} bytes", datagram.get_data().fragment_array()->size);
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
            reinterpret_cast<uint8_t*>(header_info.token.bytes),
            &header_info.token.length
    );

    if (parse_header_result < 0) {
        qlogger.warn("Failed to process a QUIC header with result: {}", parse_header_result);
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
future<> quic_server_instance<CT>::handle_pre_hs_connection(const quic_header_info& header_info,
        udp_datagram&& datagram, const quic_connection_id& key) {
    if (!quiche_version_is_supported(header_info.version)) {
        return negotiate_version(header_info, std::move(datagram));
    }

    if (header_info.token.size() == 0) {
        return quic_retry(header_info, std::move(datagram));
    }

    // TODO: Refactor this
    const auto peer_addr = datagram.get_src().as_posix_sockaddr();
    const auto peer_addr_len = sizeof(peer_addr);

    const auto local_addr = datagram.get_dst().as_posix_sockaddr();
    const auto local_addr_len = sizeof(local_addr);

    const std::optional<quic_dcid> odcid = validate_token(header_info.token, datagram.get_src());

    if (!odcid) {
        qlogger.warn("Invalid address validation token.");
        return make_ready_future<>();
    }

    quiche_conn* connection = quiche_accept(
            header_info.dcid.data,
            header_info.dcid.length,
            odcid->cid,
            odcid->size,
            &local_addr,
            local_addr_len,
            &peer_addr,
            peer_addr_len,
            _quiche_configuration.get_underlying_config()
    );

    if (connection == nullptr) {
        qlogger.info("Creating a QUIC connection has failed.");
        return make_ready_future<>();
    }

    _address_tokens.erase(datagram.get_src());

    auto conn = make_lw_shared<connection_type>(connection, this->weak_from_this(), datagram.get_src(), key);
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
        qlogger.info("Creating a packet to negotiate the version has failed.");
        return make_ready_future<>();
    }

    temporary_buffer<quic_byte_type> tb{reinterpret_cast<quic_byte_type*>(_buffer.data()), static_cast<size_t>(written)};
    send_payload payload{std::move(tb), datagram.get_src()};

    return _channel_manager.send(std::move(payload));
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::quic_retry(const quic_header_info& header_info, udp_datagram&& datagram) {
    header_token token;
    try {
        token = header_token::mint_token(
            datagram.get_src(),
            { reinterpret_cast<const char*>(header_info.dcid.data), header_info.dcid.length }
        );
    } catch (const std::exception& excp) {
        qlogger.info("Minting a token has failed with the message: {}", excp.what());
    }
    _address_tokens[datagram.get_src()] = token;
    quic_connection_id new_cid = generate_new_cid();

    const auto written = quiche_retry(
            header_info.scid.data,
            header_info.scid.length,
            header_info.dcid.data,
            header_info.dcid.length,
            new_cid.cid,
            sizeof(new_cid.cid),
            token.data(),
            token.size(),
            header_info.version,
            reinterpret_cast<uint8_t*>(_buffer.data()),
            _buffer.size()
    );

    if (written < 0) {
        qlogger.error("Failed to create a retry QUIC packet. Return value: {}\n", written);
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

// Returns the new DCID of a connection.
template<template<typename> typename CT>
std::optional<quic_dcid> quic_server_instance<CT>::validate_token(
        const header_token& token, const socket_address& sa)
{
    try {
        if (!header_token::validate_address(token, sa)) {
            return std::nullopt;
        }

        const auto& tok = _address_tokens.at(sa);
        if (std::memcmp(token.entropy_data(), tok.entropy_data(), header_token::ENTROPY_SIZE) != 0) {
            return std::nullopt;
        }

        // Extract the new DCID.
        return { token.dcid() };
    } catch (...) {
        return std::nullopt;
    }
}


} // namespace seastar::net
