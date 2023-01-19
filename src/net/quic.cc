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
#include "seastar/net/socket_defs.hh"
#include <netinet/in.h>
#include <seastar/net/quic.hh>

#include <seastar/core/future.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/api.hh>
#include <seastar/core/queue.hh>

#include <fmt/core.h>   // For development purposes, ditch this later on.

#include <quiche.h>

#include <sys/socket.h> // ::sockaddr, etc.

#include <chrono>
#include <cstring>      // std::memset, etc.
#include <random>       // Generating connection IDs
#include <queue>
#include <unordered_map>
#include <utility>
#include <vector>


namespace seastar::net {

namespace {

// Provide type safety.
constexpr size_t MAX_CONNECTION_ID_LENGTH = QUICHE_MAX_CONN_ID_LEN;
// TODO: Remove if unnecessary.
constexpr size_t MAX_DATAGRAM_SIZE = 65'507;

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
            
        // TODO: Handle this more sensibly
        assert(_config);
        
        // TODO check return value
        quiche_config_set_application_protos(
                _config,
                reinterpret_cast<const uint8_t*>(PROTOCOL_LIST),
                sizeof(PROTOCOL_LIST) - 1);

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

struct connection_id {
    uint8_t _cid[MAX_CONNECTION_ID_LENGTH];

    connection_id() {
        std::memset(_cid, 0, sizeof(_cid));
    }
    
    void generate() {
        static std::mt19937 mersenne(std::chrono::system_clock::now().time_since_epoch().count());

        constexpr size_t CID_LENGTH = sizeof(_cid);
        size_t offset = 0;
        
        while (offset < CID_LENGTH) {
            const auto random_number = mersenne();
            std::memcpy(_cid + offset, &random_number, std::min(sizeof(random_number), CID_LENGTH - offset));
            offset += sizeof(random_number);
        }
    }
    
    bool operator==(const connection_id& other) const noexcept {
        return std::memcmp(_cid, other._cid, sizeof(_cid)) == 0;
    }
};

} // anonymous namespace
} // namespace seastar::net

namespace std {

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

    quic_server_socket::quic_server_socket(std::unique_ptr<quic_server_socket_impl> impl) noexcept : _impl(std::move(impl)) { }

    future<quic_accept_result> quic_server_socket::accept() {
        return _impl->accept();
    }

    socket_address quic_server_socket::local_address() const noexcept {
        return _impl->local_address();
    }

    namespace {

class posix_quic_server_socket_impl;

class quic_connection {
private:
    quiche_conn*                                _connection     = nullptr;
    std::vector<char>                           _buffer;
    std::queue<temporary_buffer<char>>          _read_queue;
    std::queue<promise<temporary_buffer<char>>> _read_requests;

private:
    friend class posix_quic_server_socket_impl;

public:
    // For the purpose of it being the value type
    // of containers to avoid problems later on.
    // Feel free to delete it if you've made sure it's unnecessary.
    quic_connection()
    : _buffer(MAX_DATAGRAM_SIZE) {}

    quic_connection(quiche_conn* connection)
    : _connection(connection)
    , _buffer(MAX_DATAGRAM_SIZE) {}

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

    future<> service_loop() {
        // TODO: Consider changing this to seastar::repeat and passing a stop toket to it
        // once the destructor of the class has been called. Something similar to how
        // std::jthread works.
        return keep_doing([this] {
            bool fin = false;
            const auto recv_result = quiche_conn_stream_recv(
                _connection,
                0,      // TODO: Change this hardcoded stream
                reinterpret_cast<uint8_t*>(_buffer.data()),
                _buffer.size(),
                &fin
            );

            if (recv_result != QUICHE_ERR_DONE) {
                // There is a message.

                if (recv_result < 0) {
                    fmt::print("Reading from a stream has failed with message: {}\n", recv_result);
                    // TODO: Handle this properly.
                }
                /* TODO: Handle the message properly when fin == true.
                        Right now we only send an empty FIN message to the endpoint. */
                if (fin) {
                    quiche_conn_stream_send(_connection, 0, nullptr, 0, true);
                    // TODO: Do something...
                }

                temporary_buffer<char> message(_buffer.data(), recv_result);
                if (!_read_requests.empty()) {
                    auto&& promise = std::move(_read_requests.front());
                    promise.set_value(std::move(message));
                } else {
                    _read_queue.push(std::move(message));
                }
            }
            return seastar::make_ready_future<>();
        });
    }

    void write(temporary_buffer<char> tb) {
        // TODO: Handle this properly.
        [[maybe_unused]] const auto send_result = quiche_conn_stream_send(
            _connection,
            0,  // TODO: Hardcoded stream
            reinterpret_cast<const uint8_t*>(tb.get()),
            tb.size(),
            0         // Don't close the stream.
        );
    }

    future<temporary_buffer<char>> read() {
        if (_read_queue.empty()) {
            promise<temporary_buffer<char>> promise;
            auto result = promise.get_future();
            _read_requests.push(std::move(promise));
            return result;
        } else {
            auto result = std::move(_read_queue.front());
            _read_queue.pop();
            return make_ready_future<temporary_buffer<char>>(std::move(result));
        }
    }
};

class posix_quic_server_socket_impl final : public quic_server_socket_impl {
private:
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
    udp_channel                                         _udp_channel;
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
    friend class quic_connection;

public:
    explicit posix_quic_server_socket_impl(const socket_address& sa, const std::string& cert, const std::string& key,
            const quic_connection_config& quic_config)
    : _quiche_configuration(cert, key, quic_config)
    , _udp_channel(make_udp_channel(sa))
    , _buffer(MAX_DATAGRAM_SIZE)
    , _send_queue(make_ready_future<>()) {
        (void) service_loop();
    }
    
    explicit posix_quic_server_socket_impl(const std::string& cert, const std::string& key,
            const quic_connection_config& quic_config)
    : _quiche_configuration(cert, key, quic_config)
    , _udp_channel(make_udp_channel())
    , _buffer(MAX_DATAGRAM_SIZE)
    , _send_queue(make_ready_future<>()) {
        (void) service_loop();
    }

    virtual ~posix_quic_server_socket_impl() = default;

    future<> service_loop() {
        // TODO: Consider changing this to seastar::repeat and passing a stop toket to it
        // once the destructor of the class has been called.
        return keep_doing([this] {
            constexpr auto get_socket_address = [](const ::sockaddr_storage& sock_addr) {
                switch (sock_addr.ss_family) {
                case AF_INET:   return socket_address(*reinterpret_cast<const ::sockaddr_in*>(&sock_addr));
                case AF_INET6:  return socket_address(*reinterpret_cast<const ::sockaddr_in6*>(&sock_addr));
                default:        assert(false);
                }
            };

            quiche_send_info send_info;

            for (auto &[_, connection] : _connections) {
                while (true) {
                    const auto send_result = quiche_conn_send(
                        connection._connection,
                        reinterpret_cast<uint8_t*>(_buffer.data()),
                        _buffer.size(),
                        &send_info
                    );

                    if (send_result == QUICHE_ERR_DONE) {
                        fmt::print("Done writing\n");
                        break;
                    }

                    if (send_result < 0) {
                        fmt::print(stderr, "Failed to create a packet. Return value: {}\n", send_result);
                        break;
                    }

                    temporary_buffer<char> tb(_buffer.data(), send_result);
                    const auto sock = get_socket_address(send_info.to);

                    _send_queue = _send_queue.then(
                        [this, tb = std::move(tb), src_address = sock]() mutable {
                            return _udp_channel.send(src_address, std::move(tb));
                        }
                    );
                }
            }

            return _udp_channel.receive().then([this](udp_datagram datagram) {
                return handle_datagram(std::move(datagram));
            });
        });
    }

    virtual future<quic_accept_result> accept() override {
        promise<quic_accept_result> request;
        auto result = request.get_future();
        _accept_requests.push(std::move(request));
        return result;
    }

    virtual socket_address local_address() const override {
        return _udp_channel.local_address();
    }

private:
    future<> handle_datagram(udp_datagram&& datagram) {
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

        if (_connections.find(key) == _connections.end()) {
            return handle_pre_hs_connection(header_info, std::move(datagram), key);
        } else {
            return handle_post_hs_connection(_connections[key], std::move(datagram));
        }
    }

    future<> handle_post_hs_connection(quic_connection& connection, udp_datagram&& datagram) {
        auto* fa = datagram.get_data().fragment_array();
        auto local_addr = datagram.get_dst().as_posix_sockaddr();
        auto peer_addr = datagram.get_src().as_posix_sockaddr();

        quiche_recv_info recv_info = {
                &peer_addr,
                sizeof(peer_addr),
                &local_addr,
                sizeof(local_addr)
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

    
    // TODO make it look pretty :)
    static bool validate_token(const uint8_t *token, size_t token_len,
                               struct sockaddr_storage *addr, socklen_t addr_len,
                               uint8_t *odcid, size_t *odcid_len) {
        if ((token_len < sizeof("quiche") - 1) ||
            std::memcmp(token, "quiche", sizeof("quiche") - 1)) {
            return false;
        }

        token += sizeof("quiche") - 1;
        token_len -= sizeof("quiche") - 1;

        if ((token_len < addr_len) || std::memcmp(token, addr, addr_len)) {
            return false;
        }

        token += addr_len;
        token_len -= addr_len;

        if (*odcid_len < token_len) {
            return false;
        }

        memcpy(odcid, token, token_len);
        *odcid_len = token_len;

        return true;
    }

    future<> handle_pre_hs_connection(quic_header_info& header_info, udp_datagram&& datagram, connection_id& key) {
        if (!quiche_version_is_supported(header_info.version)) {
            fmt::print("Negotiating the version...\n");
            return negotiate_version(header_info, std::move(datagram));
        }

        if (header_info.token.size == 0) {
            fmt::print("quic_retry...\n");
            return quic_retry(header_info, std::move(datagram));
        }

        /* TODO: refactor it or something. */
        sockaddr addr = datagram.get_src().as_posix_sockaddr();
        socklen_t addr_len = sizeof(addr);
        
        auto *peer_addr = (struct sockaddr_storage*) &addr;
        socklen_t peer_addr_len = addr_len;
        
        sockaddr local_addr = datagram.get_dst().as_posix_sockaddr();
        socklen_t local_addr_len = sizeof(local_addr);
        
        if (!validate_token(header_info.token.data, header_info.token.size, peer_addr, peer_addr_len,
                           reinterpret_cast<uint8_t *>(header_info.odcid.data), &header_info.odcid.length)) {
            fmt::print("Invalid address validation token.");
            return make_ready_future<>();
        }

        if (_accept_requests.empty()) {
            // If there are no requests for accepting a client, ignore the message.
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
            quiche_conn_free(connection);
            return make_ready_future<>();
        } else {
            request.set_value(quic_accept_result {
                // TODO: Create real connected socket object here.
                .connection = quic_connected_socket{},
                .remote_address = datagram.get_src()
            });
            // Outer TODO: Uncomment when this works (or delete)
            // (void) it->second.service_loop(); // TODO: Think if this really is the rigth thing to do here.
        }

        return handle_post_hs_connection(it->second, std::move(datagram));
    }

    future<> negotiate_version(const quic_header_info& header_info, udp_datagram&& datagram) {
        const auto written = quiche_negotiate_version(
            header_info.scid.data,
            header_info.scid.length,
            header_info.dcid.data,
            header_info.dcid.length,
            reinterpret_cast<uint8_t*>(_buffer.data()),
            _buffer.size()
        );

        if (written < 0) {
            fmt::print(stderr, "negotiate_version: failed to create a packet. Return value: {}\n", written);
            return make_ready_future<>();
        }

        temporary_buffer<char> tb(_buffer.data(), written);
        _send_queue = _send_queue.then(
            [this, tb = std::move(tb), src_address = datagram.get_src()]() mutable {
                return _udp_channel.send(src_address, std::move(tb));
            }
        );

        return make_ready_future<>();
    }

    future<> quic_retry(const quic_header_info& header_info, udp_datagram&& datagram) {
        const ::sockaddr addr = datagram.get_src().as_posix_sockaddr();
        const ::socklen_t addr_len = sizeof(addr);

        const auto* peer_addr = reinterpret_cast<const ::sockaddr_storage*>(&addr);

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

        temporary_buffer<char> tb(_buffer.data(), written);
        _send_queue = _send_queue.then(
            [this, tb = std::move(tb), src_address = datagram.get_src()]() mutable {
                return _udp_channel.send(src_address, std::move(tb));
            }
        );

        return make_ready_future<>();
    }

    header_token<> mint_token(const quic_header_info& header_info, const ::sockaddr_storage* addr, const ::socklen_t addr_len) {
        header_token<> result;

        std::memcpy(result.data, "quiche", sizeof("quiche") - 1);
        std::memcpy(result.data + sizeof("quiche") - 1, addr, addr_len);
        std::memcpy(result.data + sizeof("quiche") - 1 + addr_len, header_info.dcid.data, header_info.dcid.length);

        result.size = sizeof("quiche") - 1 + addr_len + header_info.dcid.length;

        return result;
    }

    connection_id generate_new_cid() {
        connection_id result;

        do {
            result.generate();
        } while (_connections.find(result) != _connections.end());

        return result;
    }
};

} // anonymous namespace

quic_server_socket
quic_listen(socket_address sa, const std::string& cert_file,
            const std::string& cert_key, const quic_connection_config& quic_config)
{
    return quic_server_socket(std::make_unique<posix_quic_server_socket_impl>(sa, cert_file, cert_key, quic_config));
}

quic_server_socket
quic_listen(const std::string& cert_file, const std::string& cert_key, const quic_connection_config& quic_config)
{
    return quic_server_socket(std::make_unique<posix_quic_server_socket_impl>(cert_file, cert_key, quic_config));
}

namespace {

// ...

} // anonymous namespace

struct send_payload {
    temporary_buffer<char> buffer;
    socket_address dst;
    
    send_payload(char *buf, size_t written, struct sockaddr_storage &dest, socklen_t dest_len) :
            buffer(buf, written) 
    {
        sockaddr_in addr_in{};
        std::memcpy(&addr_in, &dest, dest_len);
        dst = addr_in; // TODO handle ipv6
    }
};

class quic_udp_channel_manager {
private:
    udp_channel channel;
    future<> write_fiber;
    future<> read_fiber;
    queue<send_payload> write_q;
    queue<udp_datagram> read_q;
    bool closed;
    
private:
    
private:
    future<> read_loop() {
        return do_until([this] { return closed; }, [this] {
            return channel.receive().then([this] (udp_datagram datagram) mutable {
                return read_q.not_full().then([this, datagram = std::move(datagram)] () mutable {
                    read_q.push(std::move(datagram));
                });
            });
        });
    }
    
    future<> write_loop() {
        return do_until([this] { return closed; }, [this] {
            return write_q.not_empty().then([this] {
                send_payload payload = write_q.pop();
                return channel.send(payload.dst, std::move(payload.buffer));
            });
        });
    }
    
public:
    quic_udp_channel_manager() :
        channel(make_udp_channel()),
        write_fiber(make_ready_future<>()),
        read_fiber(make_ready_future<>()),
        write_q(212992), // TODO: decide on what packet qs size to use
        read_q(212992),
        closed(false) {}
        
    [[nodiscard]] socket_address local_address() const {
        return channel.local_address();
    }
        
    future<> send(send_payload &&payload) {
        return write_q.not_full().then([this, payload = std::move(payload)] () mutable {
           write_q.push(std::move(payload));
        });
    }
    
    future<udp_datagram> read() {
        return read_q.not_empty().then([this] () mutable {
           return make_ready_future<udp_datagram>(read_q.pop());
        });
    }
        
    void init() {
        read_fiber = read_loop();
        write_fiber = write_loop();
    }
    
    future<> close() {
        closed = true;
        return read_fiber.then([this] () {
           return write_fiber.then([this] () {
               channel.close();
               return make_ready_future<>();
           });
        });
    }
    
};

class quic_client_connection;

class quic_client_socket : public enable_lw_shared_from_this<quic_client_socket> {
private:
    lw_shared_ptr<quic_udp_channel_manager> channel_manager;
    promise<quic_connected_socket> connected_promise;
    quiche_configuration config;
    lw_shared_ptr<quic_client_connection> connection;
    future<> receive_fiber;
    bool promise_resolved;
    
private:
    future<> receive_loop();
    future<> receive();

public:
    explicit quic_client_socket(const quic_connection_config &quic_config);
    future<quic_connected_socket> connect(socket_address sa);
    future<> send(send_payload &&payload);
};


class quic_client_connection {
private:
    quiche_conn *conn;
    lw_shared_ptr<quic_client_socket> sock;
    socket_address local_address;
    socket_address peer_address;
    timer<std::chrono::steady_clock> timeout_timer;

public:
    quic_client_connection(quiche_conn *connection, const lw_shared_ptr<quic_client_socket> &socket, 
                           socket_address la, socket_address pa) :
        conn(connection),
        sock(socket),
        local_address(la),
        peer_address(pa),
        timeout_timer() {}
        
    future<> quic_flush() {
        static uint8_t out[MAX_DATAGRAM_SIZE];
        
        return seastar::repeat([this] () {
           quiche_send_info send_info;

            ssize_t written = quiche_conn_send(conn, out, sizeof(out), &send_info);

            if (written == QUICHE_ERR_DONE) {
                return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::yes);
            }
            
            if (written < 0) {
                throw std::runtime_error("Failed to create packet.");
            }
            
            // TODO handle pacing.
            return sock->send(send_payload(reinterpret_cast<char *>(out), written, 
                                           send_info.to, send_info.to_len)).then([] () {
                return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::no);
            });
        }).then([this] () {
            auto timeout = (int64_t) quiche_conn_timeout_as_millis(conn);
            if (timeout >= 0) {
                timeout_timer.rearm(std::chrono::steady_clock::now() 
                    + std::chrono::milliseconds(timeout), std::nullopt);
            }
            return make_ready_future<>();
        });
    }
    
    future<> init() {
        timeout_timer.set_callback([this] () {
           quiche_conn_on_timeout(conn);
           (void) quic_flush();
        });
        
        return quic_flush();
    }
        
    void receive(udp_datagram &&datagram) {
        auto* fa = datagram.get_data().fragment_array();
        quiche_recv_info recv_info = {
                &peer_address.as_posix_sockaddr(),
                sizeof(peer_address.as_posix_sockaddr()),
                &local_address.as_posix_sockaddr(),
                sizeof(local_address.as_posix_sockaddr())
        };

        const auto recv_result = quiche_conn_recv(
                conn,
                reinterpret_cast<uint8_t*>(fa->base),
                fa->size,
                &recv_info
        );

        if (recv_result < 0) {
            fmt::print(stderr, "Failed to process a QUIC packet. Return value: {}\n", recv_result);
        }
    }
    
    bool is_established() {
        return quiche_conn_is_established(conn);
    }
    
    bool closed() {
        return quiche_conn_is_closed(conn);
    }
};


quic_client_socket::quic_client_socket(const quic_connection_config &quic_config) :
        channel_manager(make_lw_shared<quic_udp_channel_manager>()),
        connected_promise(),
        config(quic_config),
        connection(),
        receive_fiber(make_ready_future<>()),
        promise_resolved(false) {}
        
future<> quic_client_socket::receive() {
    return channel_manager->read().then([this] (udp_datagram &&datagram) {
        connection->receive(std::move(datagram));
        
        if (connection->closed()) {
            return make_ready_future<>();
        }
        
        if (connection->is_established() && !promise_resolved) {
            promise_resolved = true;
            connected_promise.set_value(); // TODO, pass the `quic_connection` to `quic_connected_socket`
        }
        
        return connection->quic_flush();
    });
}

future<> quic_client_socket::receive_loop() {
    return do_until([this] () { return connection->closed(); }, 
                    [this] () {
        return receive();
    }).then([this] () {
        return channel_manager->close();
    });
}

future<> quic_client_socket::send(send_payload &&payload) {
    return channel_manager->send(std::move(payload));
}
    
future<quic_connected_socket> quic_client_socket::connect(socket_address sa) {
    channel_manager->init();
    socket_address la = channel_manager->local_address();
    connection_id cid;
    cid.generate();
    quiche_conn *conn;
    
    conn = quiche_connect(
            nullptr, // TODO decide on what hostname to use
            cid._cid,
            sizeof(cid._cid),
            &la.as_posix_sockaddr(),
            sizeof(la.as_posix_sockaddr()),
            &sa.as_posix_sockaddr(),
            sizeof(sa.as_posix_sockaddr()),
            config.get_underlying_config()
    );
    
    if (!conn) {
        connected_promise.set_exception(std::runtime_error("Creating quic connection failed."));
        return connected_promise.get_future();
    }

    connection = make_lw_shared<quic_client_connection>(conn, this->shared_from_this(), la, sa);

    // TODO someone will have to clean it up, probably the `quic_connected_socket`.
    receive_fiber = receive_loop();

    return connection->init().then([this] () {
        return connected_promise.get_future();
    });
}


// Design:
// udp_channel_manager <=> socket <=> client_connection <=> data_sink/source (on top of quic_connected_socket)
// We can create 2 subclasses (client_socket, server_socket) with their corresponding logic. This way we can have 
// one implementation for the rest of the classes.
future<quic_connected_socket>
quic_connect(socket_address sa, const quic_connection_config& quic_config) {
    return seastar::do_with(quic_client_socket(quic_config), [sa] (quic_client_socket& client_socket) {
        return client_socket.connect(sa);
    });
}

} // namespace seastar::net
