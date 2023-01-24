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

#include <seastar/net/quic.hh>

#include <seastar/core/future.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/core/queue.hh>
#include <seastar/net/api.hh>
#include <seastar/net/socket_defs.hh>

#include <fmt/core.h>   // For development purposes, ditch this later on.

#include <quiche.h>

#include <chrono>
#include <cstring>      // std::memset, etc.
#include <random>       // Generating connection IDs
#include <stdexcept>
#include <unordered_map>
#include <vector>

// TODO: Think if some classes/structs should/should not be marked as `final`.

namespace seastar::net {

namespace {

// Provide type safety.
constexpr size_t MAX_CONNECTION_ID_LENGTH = QUICHE_MAX_CONN_ID_LEN;
// TODO: Remove if unnecessary.
constexpr size_t MAX_DATAGRAM_SIZE = 65'507;


//==============================
//..............................
//..............................
// Configuration of the socket.
//..............................
//..............................
//==============================


class quiche_configuration final {
private:
    // TODO: For the time being, store these statically to make development easier.
    constexpr static const char PROTOCOL_LIST[] = "\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9";

private:
    quiche_config* _config = nullptr;

public:
    quiche_configuration() = delete;
    quiche_configuration(quiche_configuration &other) = delete;
    quiche_configuration& operator=(quiche_configuration &other) = delete;

    quiche_configuration(quiche_configuration &&other) noexcept {
        _config = std::exchange(other._config, nullptr);
    }
    
    quiche_configuration& operator=(quiche_configuration &&other) noexcept {
        _config = std::exchange(other._config, nullptr);
        return *this;
    }
    
    explicit quiche_configuration(const quic_connection_config &config) 
    : _config(quiche_config_new(QUICHE_PROTOCOL_VERSION))
    {
        if (!_config) {
            throw std::bad_alloc{};
        }
        
        // TODO check return value
        quiche_config_set_application_protos(
            _config,
            reinterpret_cast<const uint8_t*>(PROTOCOL_LIST),
            sizeof(PROTOCOL_LIST) - 1
        );

        constexpr auto convert_cc = [](quic_cc_algorithm cc) noexcept -> quiche_cc_algorithm {
            switch (cc) {
                case quic_cc_algorithm::BBR:    return QUICHE_CC_BBR;
                case quic_cc_algorithm::CUBIC:  return QUICHE_CC_CUBIC;
                case quic_cc_algorithm::RENO:   return QUICHE_CC_RENO;
            }
            return QUICHE_CC_RENO;
        };

        quiche_config_set_max_idle_timeout(_config, config.max_idle_timeout);
        quiche_config_set_max_recv_udp_payload_size(_config, config.max_recv_udp_payload_size);
        quiche_config_set_max_send_udp_payload_size(_config, config.max_send_udp_payload_size);
        quiche_config_set_initial_max_data(_config, config.initial_max_data);
        quiche_config_set_initial_max_stream_data_bidi_local(_config, config.initial_max_stream_data_bidi_local);
        quiche_config_set_initial_max_stream_data_bidi_remote(_config, config.initial_max_stream_data_bidi_remote);
        quiche_config_set_initial_max_stream_data_uni(_config, config.initial_max_stream_data_uni);
        quiche_config_set_initial_max_streams_bidi(_config, config.initial_max_streams_bidi);
        quiche_config_set_initial_max_streams_uni(_config, config.initial_max_streams_uni);
        quiche_config_set_disable_active_migration(_config, config.disable_active_migration);
        quiche_config_set_cc_algorithm(_config, convert_cc(config.congestion_control_algorithm));
        quiche_config_set_max_stream_window(_config, config.max_stream_window);
        quiche_config_set_max_connection_window(_config, config.max_connection_window);
    }

    quiche_configuration(const std::string& cert_filepath, const std::string& key_filepath,
            const quic_connection_config& config)
    : quiche_configuration(config)
    {
        const auto handle_quiche_err = [&](auto return_code, const auto &msg) {
            constexpr decltype(return_code) OK_CODE = 0;
            if (return_code != OK_CODE) {
                // TODO: For the time being, to make development a bit easier.
                fmt::print(stderr, "Error while initializing the QUIC configuration: \"{}\"", msg);
                throw std::runtime_error("Could not initialize a quiche configuration.");
            }
        };

        handle_quiche_err(
            quiche_config_load_cert_chain_from_pem_file(_config, cert_filepath.c_str()),
            "Loading the certificate file has failed."
        );
        handle_quiche_err(
            quiche_config_load_priv_key_from_pem_file(_config, key_filepath.c_str()),
            "Loading the key file has failed."
        );
    }

    ~quiche_configuration() {
        if (_config) {
            quiche_config_free(std::exchange(_config, nullptr));
        }
    }

    quiche_config* get_underlying_config() noexcept {
        return _config;
    }
};


//========================
//........................
//........................
// Connection identifier.
//........................
//........................
//========================


struct connection_id {
    uint8_t _cid[MAX_CONNECTION_ID_LENGTH];

    connection_id() {
        std::memset(_cid, 0, sizeof(_cid));
    }
    
    static connection_id generate() {
        static std::mt19937 mersenne(std::chrono::system_clock::now().time_since_epoch().count());

        connection_id result;

        constexpr size_t CID_LENGTH = sizeof(_cid);
        size_t offset = 0;
        
        while (offset < CID_LENGTH) {
            const auto random_number = mersenne();
            std::memcpy(result._cid + offset, &random_number, std::min(sizeof(random_number), CID_LENGTH - offset));
            offset += sizeof(random_number);
        }

        return result;
    }
    
    bool operator==(const connection_id& other) const noexcept {
        return std::memcmp(_cid, other._cid, sizeof(_cid)) == 0;
    }
};

} // anonymous namespace
} // namespace seastar::net

namespace std {

// So that `std::unordered_map` can use `connection_id` as the key type.
template<>
struct hash<seastar::net::connection_id> {
    size_t operator()(seastar::net::connection_id cid) const noexcept {
        size_t result = 0;
        for (auto it = std::begin(cid._cid); it != std::end(cid._cid); ++it) {
            result ^= *it + 0x9e3779b9
                    + (seastar::net::MAX_CONNECTION_ID_LENGTH << 6)
                    + (seastar::net::MAX_CONNECTION_ID_LENGTH >> 2);
        }
        return result;
    }
};

} // namespace std

namespace seastar::net {
namespace {


//=====================
//.....................
//.....................
// Network UDP manager
//.....................
//.....................
//=====================


struct send_payload {
    temporary_buffer<char>  buffer;
    socket_address          dst;

    send_payload(const char* buf, size_t size, const socket_address& sa)
    : buffer(buf, size)
    , dst(sa) {}
    
    send_payload(const char* buf, size_t size, const ::sockaddr_storage &dest, ::socklen_t dest_len)
    : buffer(buf, size) 
    {
        ::sockaddr_in addr_in{};
        std::memcpy(&addr_in, &dest, dest_len);
        dst = addr_in; // TODO: handle ipv6
    }
};

class quic_udp_channel_manager {
private:
    constexpr static size_t WRITE_QUEUE_SIZE = 212992;
    constexpr static size_t READ_QUEUE_SIZE = 212992;

private:
    udp_channel         _channel;
    future<>            _write_fiber;
    future<>            _read_fiber;
    queue<send_payload> _write_queue;
    queue<udp_datagram> _read_queue;
    bool                _closed;
    
public:
    quic_udp_channel_manager()
    : _channel(make_udp_channel())
    , _write_fiber(make_ready_future<>())
    , _read_fiber(make_ready_future<>())
    , _write_queue(WRITE_QUEUE_SIZE) // TODO: decide on what packet qs size to use
    , _read_queue(READ_QUEUE_SIZE)
    , _closed(false) {}

    quic_udp_channel_manager(udp_channel&& channel)
    : _channel(std::move(channel))
    , _write_fiber(make_ready_future<>())
    , _read_fiber(make_ready_future<>())
    , _write_queue(WRITE_QUEUE_SIZE) // TODO: decide on what packet qs size to use
    , _read_queue(READ_QUEUE_SIZE)
    , _closed(false) {}
        
    [[nodiscard]] socket_address local_address() const {
        return _channel.local_address();
    }
        
    future<> send(send_payload&& payload) {
        return _write_queue.not_full().then([this, payload = std::move(payload)]() mutable {
            _write_queue.push(std::move(payload));
        });
    }
    
    future<udp_datagram> read() {
        return _read_queue.not_empty().then([this]() {
            return make_ready_future<udp_datagram>(_read_queue.pop());
        });
    }
        
    void init() {
        _read_fiber = read_loop();
        _write_fiber = write_loop();
    }
    
    future<> close() {
        _closed = true;
        return _read_fiber.then([this] () {
            return _write_fiber.then([this] () {
                _channel.close();
                return make_ready_future<>();
            });
        });
    }

private:
    future<> read_loop() {
        return do_until([this] { return _closed; }, [this] {
            return _channel.receive().then([this](udp_datagram datagram) {
                return _read_queue.not_full().then([this, datagram = std::move(datagram)]() mutable {
                    _read_queue.push(std::move(datagram));
                });
            });
        });
    }
    
    future<> write_loop() {
        return do_until([this] { return _closed; }, [this] {
            return _write_queue.not_empty().then([this] {
                send_payload payload = _write_queue.pop();
                return _channel.send(payload.dst, std::move(payload.buffer));
            });
        });
    }
};


//====================
//....................
//....................
// QUIC server socket
//....................
//....................
//====================


// TODO: If you think this is a good idea,
// create a CRTP struct for static polymorphism for
// the server and client structures. They share the same
// interface, so that will reduce code duplication
// with no performance loss (due to the compiler's optimizations).

// TODO: Give it a thought if this really is necessary.
// Maybe there are other, better ways to solve it than making
// `posix_quic_server_socket_impl` a friend of `quic_connection`.
class posix_quic_server_socket_impl;

// Class representing a single connection created by a QUIC server.
class quic_connection {
private:
    // TODO: How much should it be? Or should we only read when necessary?
    constexpr static size_t STREAM_READ_QUEUE_SIZE = 10000;

private:
    quiche_conn*                                _connection     = nullptr;
    std::vector<char>                           _buffer;
    queue<temporary_buffer<char>>               _read_queue;
    promise<>                                   _readable;

private:
    friend class posix_quic_server_socket_impl;

public:
    // For the purpose of it being the value type
    // of containers to avoid problems later on.
    // Feel free to delete it if you've made sure it's unnecessary.
    quic_connection()
    : _buffer(MAX_DATAGRAM_SIZE)
    , _read_queue(STREAM_READ_QUEUE_SIZE) {}

    quic_connection(quiche_conn* connection)
    : _connection(connection)
    , _buffer(MAX_DATAGRAM_SIZE)
    , _read_queue(STREAM_READ_QUEUE_SIZE) {}

    ~quic_connection() {
        // TODO: Right now, this destructor is more proof-of-concept-like
        // rather than something production-ready.
        // For more information, see e.g. quiche_conn_close
        // -- right now, we don't handle it at all, but it
        // might require destructing this object.
        // Please, handle it more "gently".
        if (_connection) {
            quiche_conn_free(std::exchange(_connection, nullptr));
        }
    }

    future<> service_loop();
    void write(temporary_buffer<char> tb, std::uint64_t stream_id);
    future<temporary_buffer<char>> read();
};

future<> quic_connection::service_loop() {
    // TODO: Consider changing this to seastar::repeat and passing a stop toket to it
    // once the destructor of the class has been called. Something similar to how
    // std::jthread works.
    return keep_doing([this] {
        return _readable.get_future().then([this] {
            std::uint64_t stream_id;
            auto iter = quiche_conn_readable(_connection);
            while (quiche_stream_iter_next(iter, &stream_id)) {
                bool fin = false;
                const auto recv_result = quiche_conn_stream_recv(
                        _connection,
                        stream_id,
                        reinterpret_cast<uint8_t*>(_buffer.data()),
                        _buffer.size(),
                        &fin
                );

                if (recv_result < 0) {
                    fmt::print("Reading from a stream has failed with message: {}\n", recv_result);
                    // TODO: Handle this properly.
                } else {
                    /* TODO: Handle the message properly when fin == true.
                            Right now we only send an empty FIN message to the endpoint. */
                    if (fin) {
                        quiche_conn_stream_send(_connection, stream_id, nullptr, 0, true);
                        // TODO: Do something...
                    }

                    temporary_buffer<char> message(_buffer.data(), recv_result);
                    _read_queue.push(std::move(message));
                }
            }
            if (!quiche_conn_is_readable(_connection)) {
                _readable = promise<>();
            }
            return make_ready_future<>();
        });
    });
}

[[maybe_unused]] void quic_connection::write(temporary_buffer<char> tb, std::uint64_t stream_id) {
    // TODO: Handle this properly.
    [[maybe_unused]] const auto send_result = quiche_conn_stream_send(
        _connection,
        stream_id,
        reinterpret_cast<const uint8_t*>(tb.get()),
        tb.size(),
        0         // Don't close the stream.
    );
}

[[maybe_unused]] future<temporary_buffer<char>> quic_connection::read() {
    return _read_queue.pop_eventually();
}

// TODO: Try to get rid of the POSIX networking structures
// if possible.
class posix_quic_server_socket_impl final : public quic_server_socket_impl {
private:
    // TODO: Check the comments left in the function `quic_retry`.
    // Right now, tokens aren't used properly and passing `socket_address::length()`
    // to quiche's functions causes validation of them return false. Investigate it.
    constexpr static size_t MAX_TOKEN_SIZE =
            sizeof("quiche") - 1 + sizeof(::sockaddr_storage) + MAX_CONNECTION_ID_LENGTH;
    
template<size_t Length = MAX_CONNECTION_ID_LENGTH>
    struct cid {
        uint8_t data[Length];
        size_t length = sizeof(data);
    };

    template<size_t TokenSize = MAX_TOKEN_SIZE>
    struct header_token {
        uint8_t data[TokenSize];
        size_t size = sizeof(data);
    };

    struct quic_header_info {
        uint8_t type;
        uint32_t version;

        cid<> scid;
        cid<> dcid;
        cid<> odcid;

        header_token<> token;
    };

private:
    quiche_configuration                                _quiche_configuration;
    // TODO: The commented-out `quic_udp_channel_manager` doesn't work with
    // the server class as of now. It seems the client doesn't receive
    // any messages from the server when it's used. Come up with a solution.
    udp_channel                                         _udp_channel;
    // quic_udp_channel_manager                            _udp_manager;
    // Local buffer for receiving bytes from the network.
    // Use std::vector instead of an automatic memory container
    // to avoid stack overflows.
    std::vector<char>                                   _buffer;
    std::queue<promise<quic_accept_result>>             _accept_requests;
    // TODO: Consider using std::map or std::vector instead. Pros:
    //       * no need to provide a hashing function
    //       * might be faster for fewer connections
    // Best if we could use std::colony (C++23) or some equivalent of it.
    //
    // Note: Since we iterate over the connections every time we enter
    // the service loop, providing a cache-friendly data structure
    // is crucial. On the other hand, handling each of them may
    // take a considerable amount of time, and in that case, it wouldn't
    // be that much of a problem, i.e. it wouldn't be a bottleneck.
    std::unordered_map<connection_id, quic_connection>  _connections;
    future<>                                            _send_queue;

private:
    // TODO: Is this necessary?
    friend class quic_connection;

public:
    explicit posix_quic_server_socket_impl(const socket_address& sa, const std::string& cert, const std::string& key,
            const quic_connection_config& quic_config)
    : _quiche_configuration(cert, key, quic_config)
    // , _udp_manager(make_udp_channel(sa))
    , _udp_channel(make_udp_channel(sa))
    , _buffer(MAX_DATAGRAM_SIZE)
    , _send_queue(make_ready_future<>())
    {
        (void) service_loop();
    }

    explicit posix_quic_server_socket_impl(const std::string& cert, const std::string& key,
            const quic_connection_config& quic_config)
    : _quiche_configuration(cert, key, quic_config)
    // , _udp_manager(make_udp_channel())
    , _udp_channel(make_udp_channel())
    , _buffer(MAX_DATAGRAM_SIZE)
    , _send_queue(make_ready_future<>())
    {
        (void) service_loop();
    }

    virtual ~posix_quic_server_socket_impl() = default;

    future<> service_loop();
    virtual future<quic_accept_result> accept() override;
    virtual socket_address local_address() const override;

private:
    future<> handle_datagram(udp_datagram&& datagram);
    future<> handle_post_hs_connection(quic_connection& connection, udp_datagram&& datagram);
    // TODO: Change this function to something proper, less C-like.
    static bool validate_token(const uint8_t* token, size_t token_len, const ::sockaddr_storage* addr,
            ::socklen_t addr_len, uint8_t* odcid, size_t* odcid_len);
    // TODO: Check if we cannot provide const references here instead.
    future<> handle_pre_hs_connection(quic_header_info& header_info, udp_datagram&& datagram, connection_id& key);
    future<> negotiate_version(const quic_header_info& header_info, udp_datagram&& datagram);
    future<> quic_retry(const quic_header_info& header_info, udp_datagram&& datagram);
    header_token<> mint_token(const quic_header_info& header_info, const ::sockaddr_storage* addr, const ::socklen_t addr_len);
    connection_id generate_new_cid();
};

future<> posix_quic_server_socket_impl::service_loop() {
    // TODO: Consider changing this to seastar::repeat and passing a stop toket to it
    // once the destructor of the class has been called.
    return keep_doing([this] {
        quiche_send_info send_info;

        // TODO: Change this to something more efficient.
        // If I remember correctly, quiche has some function
        // returning an iterator over the connections that
        // have some data to send.
        for (auto& [_, connection] : _connections) {
            if (quiche_conn_is_readable(connection._connection)) {
                connection._readable.set_value();
            }

            while (true) {
                const auto send_result = quiche_conn_send(
                    connection._connection,
                    reinterpret_cast<uint8_t*>(_buffer.data()),
                    _buffer.size(),
                    &send_info
                );

                if (send_result == QUICHE_ERR_DONE) {
                    // TODO: I would delete this print, it only clutters the output.
                    // fmt::print("Done writing\n");
                    break;
                }

                if (send_result < 0) {
                    fmt::print(stderr, "Failed to create a packet. Return value: {}\n", send_result);
                    break;
                }

                send_payload payload(_buffer.data(), send_result, send_info.to, send_info.to_len);
                _send_queue = _send_queue.then(
                    [this, payload = std::move(payload)]() mutable {
                        return _udp_channel.send(payload.dst, std::move(payload.buffer));
                    }
                );
            }
        }

        return _udp_channel.receive().then([this](udp_datagram datagram) {
            return handle_datagram(std::move(datagram));
        });
    });
}

future<quic_accept_result> posix_quic_server_socket_impl::accept() {
    promise<quic_accept_result> request;
    auto result = request.get_future();
    _accept_requests.push(std::move(request));
    return result;
}

socket_address posix_quic_server_socket_impl::local_address() const {
    return _udp_channel.local_address();
}

future<> posix_quic_server_socket_impl::handle_datagram(udp_datagram&& datagram) {
    quic_header_info header_info;

    const auto* fa = datagram.get_data().fragment_array();
    std::memcpy(_buffer.data(), fa->base, fa->size);

    connection_id key;

    const auto parse_header_result = quiche_header_info(
        reinterpret_cast<uint8_t*>(_buffer.data()),
        fa->size,
        sizeof(key._cid),
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
        fmt::print(stderr, "Failed to parse a QUIC header: {}\n", parse_header_result);
        return make_ready_future<>();
    }

    std::memcpy(key._cid, header_info.dcid.data, header_info.dcid.length);

    auto it = _connections.find(key);
    if (it == _connections.end()) {
        return handle_pre_hs_connection(header_info, std::move(datagram), key);
    } else {
        return handle_post_hs_connection(it->second, std::move(datagram));
    }
}

future<> posix_quic_server_socket_impl::handle_post_hs_connection(quic_connection& connection, udp_datagram&& datagram) {
    auto* fa = datagram.get_data().fragment_array();
    // TODO: Changing `from_len` and `to_len` to `socket_address::length()` function calls
    // cause the server to crash. Quiche panics:
    //   panicked at 'assertion failed: addr_len as usize == std::mem::size_of::<sockaddr_in>()'
    //   --- function `std_addr_from_c` in quiche/src/ffi.rs:1320:13
    // Check the comments in the function `quic_retry` for more information.
    const quiche_recv_info recv_info = {
        .from       = &datagram.get_src().as_posix_sockaddr(),
        .from_len   = sizeof(datagram.get_src().as_posix_sockaddr()),
        .to         = &datagram.get_dst().as_posix_sockaddr(),
        .to_len     = sizeof(datagram.get_dst().as_posix_sockaddr())
    };

    const auto recv_result = quiche_conn_recv(
        connection._connection,
        reinterpret_cast<uint8_t*>(fa->base),
        fa->size,
        &recv_info
    );

    if (recv_result < 0) {
        fmt::print(stderr, "Failed to process a QUIC packet. Return value: {}\n", recv_result);
        return make_ready_future<>();
    }

    return make_ready_future<>();
}

bool posix_quic_server_socket_impl::validate_token(const uint8_t* token, size_t token_len,
        const ::sockaddr_storage* addr, ::socklen_t addr_len, uint8_t* odcid, size_t* odcid_len)
{
    if (token_len < sizeof("quiche") - 1 || std::memcmp(token, "quiche", sizeof("quiche") - 1)) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if (token_len < addr_len || std::memcmp(token, addr, addr_len)) {
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

future<> posix_quic_server_socket_impl::handle_pre_hs_connection(quic_header_info& header_info, udp_datagram&& datagram, connection_id& key) {
    if (!quiche_version_is_supported(header_info.version)) {
        fmt::print("Negotiating the version...\n");
        return negotiate_version(header_info, std::move(datagram));
    }

    if (header_info.token.size == 0) {
        fmt::print("quic_retry...\n");
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

    if (_accept_requests.empty()) {
        // If there are no requests for accepting a client, ignore the message.
        // TODO: If I remember correctly, this is in opposition with how
        // it's managed in the TCP stack where we accept
        // everyone and only when someone requests,
        // we return a socket. Check that.
        return make_ready_future<>();
    }

    auto request = std::move(_accept_requests.front());
    _accept_requests.pop();

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
        fmt::print(stderr, "Creating a connection has failed.\n");
        return make_ready_future<>();
    }

    auto [it, succeeded] = _connections.emplace(key, connection);
    if (!succeeded) {
        fmt::print("Emplacing a connection has failed.\n");
        // TODO: Check if this can cause a double-free.
        quiche_conn_free(connection);
        return make_ready_future<>();
    } else {
        request.set_value(quic_accept_result {
            .connection     = quic_connected_socket{},
            .remote_address = datagram.get_src()
        });
        // TODO: Think if this really is the rigth thing to do here.
        (void) it->second.service_loop();
    }

    return handle_post_hs_connection(it->second, std::move(datagram));
}

future<> posix_quic_server_socket_impl::negotiate_version(const quic_header_info& header_info, udp_datagram&& datagram) {
    const auto written = quiche_negotiate_version(
        header_info.scid.data,
        header_info.scid.length,
        header_info.dcid.data,
        header_info.dcid.length,
        reinterpret_cast<uint8_t*>(_buffer.data()),
        _buffer.size()
    );

    if (written < 0) {
        fmt::print(stderr, "negotiate_version: failed to created a packet. Return value: {}\n", written);
        return make_ready_future<>();
    }

    send_payload payload(
        _buffer.data(),
        written,
        datagram.get_src()
    );

    _send_queue = _send_queue.then(
        [this, payload = std::move(payload)]() mutable {
            // return _udp_manager.send(std::move(payload));
            return _udp_channel.send(payload.dst, std::move(payload.buffer));
        }
    );

    return make_ready_future<>();
}

future<> posix_quic_server_socket_impl::quic_retry(const quic_header_info& header_info, udp_datagram&& datagram) {
    const auto addr = datagram.get_src().as_posix_sockaddr();
    const auto* peer_addr = reinterpret_cast<const ::sockaddr_storage*>(&addr);
    // TODO: Changing this to `datagram.get_src().length()`, which, to my understanding, should be
    // the right thing to do, causes validating the token return false later on. I think we should review
    // how exactly we use sizes of the address structs.
    const auto addr_len = sizeof(addr);

    const auto token = mint_token(header_info, peer_addr, addr_len);
    connection_id new_cid = generate_new_cid();

    const auto written = quiche_retry(
        header_info.scid.data,
        header_info.scid.length,
        header_info.dcid.data,
        header_info.dcid.length,
        new_cid._cid,
        sizeof(new_cid._cid),
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

    send_payload payload(_buffer.data(), written, datagram.get_src());
    _send_queue = _send_queue.then(
        [this, payload = std::move(payload)]() mutable {
            return _udp_channel.send(payload.dst, std::move(payload.buffer));
        }
    );

    return make_ready_future<>();
}

posix_quic_server_socket_impl::header_token<> posix_quic_server_socket_impl::mint_token(const quic_header_info& header_info,
        const ::sockaddr_storage* addr, const ::socklen_t addr_len)
{
    header_token<> result;

    std::memcpy(result.data, "quiche", sizeof("quiche") - 1);
    std::memcpy(result.data + sizeof("quiche") - 1, addr, addr_len);
    std::memcpy(result.data + sizeof("quiche") - 1 + addr_len, header_info.dcid.data, header_info.dcid.length);

    result.size = sizeof("quiche") - 1 + addr_len + header_info.dcid.length;

    return result; 
}

connection_id posix_quic_server_socket_impl::generate_new_cid() {
    connection_id result;

    do {
        result = connection_id::generate();
    } while (_connections.find(result) != _connections.end());

    return result;
}


//====================
//....................
//....................
// QUIC client socket
//....................
//....................
//====================


class quic_client_connection;

class quic_client_socket : public enable_lw_shared_from_this<quic_client_socket> {
private:
    lw_shared_ptr<quic_udp_channel_manager> _channel_manager;
    promise<quic_connected_socket>          _connected_promise;
    quiche_configuration                    _config;
    lw_shared_ptr<quic_client_connection>   _connection;
    future<>                                _receive_fiber;
    bool                                    _promise_resolved;

public:
    explicit quic_client_socket(const quic_connection_config& quic_config)
    : _channel_manager(make_lw_shared<quic_udp_channel_manager>())
    , _connected_promise()
    , _config(quic_config)
    , _connection()
    , _receive_fiber(make_ready_future<>())
    , _promise_resolved(false) {}

    future<quic_connected_socket> connect(socket_address sa);
    future<> send(send_payload&& payload);

private:
    future<> receive_loop();
    future<> receive();
};

class quic_client_connection {
private:
    quiche_conn*                        _connection;
    lw_shared_ptr<quic_client_socket>   _socket;
    socket_address                      _local_address;
    socket_address                      _peer_address;
    timer<std::chrono::steady_clock>    _timeout_timer;

public:
    quic_client_connection(quiche_conn* connection, const lw_shared_ptr<quic_client_socket>& socket,
            socket_address la, socket_address pa)
    : _connection(connection)
    , _socket(socket)
    , _local_address(la)
    , _peer_address(pa)
    , _timeout_timer() {}

    future<> quic_flush();
    future<> init();
    void receive(udp_datagram&& datagram);
    bool is_established();
    bool is_closed();
};

future<quic_connected_socket> quic_client_socket::connect(socket_address sa) {
    _channel_manager->init();

    const socket_address la = _channel_manager->local_address();
    connection_id cid = connection_id::generate();
    
    auto* connection_ptr = quiche_connect(
        nullptr,    // TODO: Decide on the hostname
        cid._cid,
        sizeof(cid._cid),
        &la.as_posix_sockaddr(),
        la.length(),
        &sa.as_posix_sockaddr(),
        sa.length(),
        _config.get_underlying_config()
    );

    if (!connection_ptr) {
        _connected_promise.set_exception(std::runtime_error("Creating a QUIC connection has failed."));
        return _connected_promise.get_future();
    }

    _connection = make_lw_shared<quic_client_connection>(connection_ptr, this->shared_from_this(), la, sa);

    // TODO: Something must clean this up afterwards, most likely `quic_connected_socket`.
    _receive_fiber = receive_loop();

    return _connection->init().then([this] {
        return _connected_promise.get_future();
    });
}

future<> quic_client_socket::send(send_payload&& payload) {
    return _channel_manager->send(std::move(payload));
}

future<> quic_client_socket::receive_loop() {
    return do_until(
        [this] { return _connection->is_closed(); },
        [this] { return receive(); }
    ).then([this] { return _channel_manager->close(); });
}

future<> quic_client_socket::receive() {
    return _channel_manager->read().then([this](udp_datagram&& datagram) {
        _connection->receive(std::move(datagram));

        if (_connection->is_closed()) {
            return make_ready_future<>();
        }

        if (_connection->is_established() && !_promise_resolved) {
            _promise_resolved = true;
            // TODO: pass the `quic_connection` to `quic_connected_socket`.
            _connected_promise.set_value();
        }

        return _connection->quic_flush();
    });
}

future<> quic_client_connection::quic_flush() {
    // TODO: Is it really a good idea to allocate this statically?
    static uint8_t out[MAX_DATAGRAM_SIZE];

    return repeat([this] {
        quiche_send_info send_info;

        const auto written = quiche_conn_send(_connection, out, sizeof(out), &send_info);

        if (written == QUICHE_ERR_DONE) {
            return make_ready_future<stop_iteration>(stop_iteration::yes);
        }

        if (written < 0) {
            throw std::runtime_error("Failed to create a packet.");
        }

        // TODO: Handle pacing.
        send_payload payload(reinterpret_cast<char*>(out), written, send_info.to, send_info.to_len);
        return _socket->send(std::move(payload)).then([] {
            return make_ready_future<stop_iteration>(stop_iteration::no);
        });
    }).then([this] {
        const auto timeout = static_cast<int64_t>(quiche_conn_timeout_as_millis(_connection));
        if (timeout >= 0) {
            _timeout_timer.rearm(std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout));
        }
        return make_ready_future<>();
    });
}

future<> quic_client_connection::init() {
    _timeout_timer.set_callback([this] {
        quiche_conn_on_timeout(_connection);
        (void) quic_flush();
    });

    // A client ought to flush after the initialization.
    return quic_flush();
}

void quic_client_connection::receive(udp_datagram&& datagram) {
    auto* fa = datagram.get_data().fragment_array();
    const quiche_recv_info recv_info = {
        .from       = &_peer_address.as_posix_sockaddr(),
        .from_len   = _peer_address.length(),
        .to         = &_local_address.as_posix_sockaddr(),
        .to_len     = _local_address.length() 
    };

    const auto recv_result = quiche_conn_recv(
        _connection,
        reinterpret_cast<uint8_t*>(fa->base),
        fa->size,
        &recv_info
    );

    if (recv_result < 0) {
        fmt::print(stderr, "Failed to process a QUIC packet. Return value: {}\n", recv_result);
    }
}

bool quic_client_connection::is_established() {
    return quiche_conn_is_established(_connection);
}

bool quic_client_connection::is_closed() {
    return quiche_conn_is_closed(_connection);
}

} // anonymous namespace

quic_server_socket quic_listen(socket_address sa, const std::string& cert_file,
        const std::string& cert_key, const quic_connection_config& quic_config)
{
    return quic_server_socket(std::make_unique<posix_quic_server_socket_impl>(sa, cert_file, cert_key, quic_config));
}

quic_server_socket quic_listen(const std::string& cert_file, const std::string& cert_key,
        const quic_connection_config& quic_config)
{
    return quic_server_socket(std::make_unique<posix_quic_server_socket_impl>(cert_file, cert_key, quic_config));
}

// Design:
// udp_channel_manager <=> socket <=> client_connection <=> data_sink/source (on top of quic_connected_socket)
// We can create 2 subclasses (client_socket, server_socket) with their corresponding logic. This way we can have 
// one implementation for the rest of the classes.
future<quic_connected_socket> quic_connect(socket_address sa, const quic_connection_config& quic_config) {
    return seastar::do_with(make_lw_shared<quic_client_socket>(quic_config),
            [sa](lw_shared_ptr<quic_client_socket> client_socket) {
        return client_socket->connect(sa);
    });
}

} // namespace seastar::net