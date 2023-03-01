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
#include <seastar/core/weak_ptr.hh>
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
#include <utility>
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


class user_closed_connection_exception : public std::exception {
    [[nodiscard]] const char* what() const noexcept override {
        return "User closed the connection.";
    }
};


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
    uint8_t _cid[MAX_CONNECTION_ID_LENGTH]{};

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
    
    explicit quic_udp_channel_manager(socket_address sa)
    : _channel(make_udp_channel(sa))
    , _write_fiber(make_ready_future<>())
    , _read_fiber(make_ready_future<>())
    , _write_queue(WRITE_QUEUE_SIZE) // TODO: decide on what packet qs size to use
    , _read_queue(READ_QUEUE_SIZE)
    , _closed(false) {}


    [[nodiscard]] socket_address local_address() const {
        return _channel.local_address();
    }

    future<> send(send_payload&& payload) {
        return _write_queue.push_eventually(std::move(payload));
    }

    future<udp_datagram> read() {
        return _read_queue.pop_eventually();
    }

    void init() {
        _read_fiber = read_loop();
        _write_fiber = write_loop();
    }

    future<> close() {
        _closed = true;
        _channel.shutdown_input();
        return _read_fiber.handle_exception([this] (const std::exception_ptr &e) {
            return _write_fiber.handle_exception([this] (const std::exception_ptr &e) {
                _channel.close();
                return make_ready_future<>();
            });
        });
    }
    
    void abort_queues(std::exception_ptr &&ex) {
        _write_queue.abort(ex);
        _read_queue.abort(ex);
    }

private:
    future<> read_loop() {
        return do_until([this] { return _closed; }, [this] {
            return _channel.receive().then([this] (udp_datagram datagram) {
                return _read_queue.push_eventually(std::move(datagram));
            });
        });
    }

    future<> write_loop() {
        return do_until([this] { return _closed; }, [this] {
            return _write_queue.pop_eventually().then([this] (send_payload payload) {
                return _channel.send(payload.dst, std::move(payload.buffer));
            });
        });
    }
};


// TODO: If you think this is a good idea,
// create a CRTP struct for static polymorphism for
// the server and client structures. They share the same
// interface, so that will reduce code duplication
// with no performance loss (due to the compiler's optimizations).


class quic_server_socket_quiche_impl;
class quic_client_socket;

//====================
//....................
//....................
// QUIC connection
//....................
//....................
//====================


template <typename Socket>
class quic_connection {
private:
    friend class quic_client_socket;
    friend class quic_server_socket_quiche_impl;

private:
    constexpr static size_t STREAM_READ_QUEUE_SIZE = 10000;

private:
    quiche_conn*                                                          _connection;
    std::vector<char>                                                     _buffer;
    std::unordered_map<std::uint64_t, queue<temporary_buffer<char>>>      _read_queues;
    std::unordered_map<std::uint64_t, std::deque<temporary_buffer<char>>> _write_queues;
    std::unordered_map<std::uint64_t, promise<>>                          _writable_promises;
    std::unordered_map<std::uint64_t, promise<>>                          _input_shutdown_promises;
    promise<>                                                             _readable;
    weak_ptr<Socket>                                                      _socket;
    socket_address                                                        _local_address;
    socket_address                                                        _peer_address;
    timer<std::chrono::steady_clock>                                      _timeout_timer;
    future<>                                                              _stream_recv_fiber;
    bool                                                                  _closing = false;

public:
    bool                                                                  _read_future_resolved = false;
    lw_shared_ptr<Socket> just_to_live; // TODO: remove this, think of a solution for the ownership of that

private:
    future<> stream_recv_loop();
    future<> wait_send_available(std::uint64_t stream_id);
    void send_outstanding_data_in_streams_if_possible();

public:
    quic_connection(quiche_conn* connection, weak_ptr<Socket> socket,
                           socket_address la, socket_address pa)
            : _connection(connection)
            , _buffer(MAX_DATAGRAM_SIZE)
            , _socket(std::move(socket))
            , _local_address(la)
            , _peer_address(pa)
            , _timeout_timer()
            , _stream_recv_fiber(make_ready_future<>())
    {}

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

    future<> quic_flush();
    future<> init();
    void receive(udp_datagram&& datagram);
    bool is_established();
    bool is_closed();
    future<> write(temporary_buffer<char> tb, std::uint64_t stream_id);
    future<temporary_buffer<char>> read(std::uint64_t stream_id);
    void shutdown_input(std::uint64_t id);
    void shutdown_output(std::uint64_t stream_id);
    future <> wait_input_shutdown(std::uint64_t stream_id);
    future<> close();
    future<> close(std::uint64_t stream_id);
};


template <typename Socket>
future<> quic_connection<Socket>::quic_flush() {
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


template <typename Socket>
future<> quic_connection<Socket>::stream_recv_loop() {
    return do_until([this] () { return quiche_conn_is_closed(_connection) || _closing; }, [this] {
        return _readable.get_future().then([this] {
            std::uint64_t stream_id;
            auto iter = quiche_conn_readable(_connection);
            while (quiche_stream_iter_next(iter, &stream_id)) {
                if (quiche_conn_stream_finished(_connection, stream_id)) {
                    _read_queues.try_emplace(stream_id, STREAM_READ_QUEUE_SIZE).first->second.push(temporary_buffer<char>("", 0));
                   //_input_shutdown_promises.try_emplace(stream_id).first->second.set_value();
                    continue;
                }

                while(quiche_conn_stream_readable(_connection, stream_id)) {
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
                        temporary_buffer<char> message(_buffer.data(), recv_result);
                        // TODO: wrap this in some kind of `not_full` future.
                        // (or just read only when necessary)
                        auto pushed = _read_queues.try_emplace(stream_id, STREAM_READ_QUEUE_SIZE).first->second.push(std::move(message));
                        if (!pushed) {
                            fmt::print("The read queue is full. Dropping the message.\n");
                        }

                        /* TODO: Handle the message properly when fin == true.
                                Right now we only send an empty FIN message to the endpoint. */
                        if (fin) {
                            quiche_conn_stream_send(_connection, stream_id, nullptr, 0, true);
                            // Push the empty buffer (interpreted as EOF).
                            pushed = _read_queues.try_emplace(stream_id, STREAM_READ_QUEUE_SIZE).first->second.push({});
                            if (!pushed) {
                                fmt::print("The read queue is full. Dropping the message.\n");
                            }
                        }
                    }
                }
            }
            quiche_stream_iter_free(iter);

            if (!quiche_conn_is_readable(_connection)) {
                _readable = promise<>();
                _read_future_resolved = false;
            }
            return make_ready_future<>();
        });
    });
}

template <typename Socket>
future<> quic_connection<Socket>::wait_send_available(std::uint64_t stream_id) {
    auto capacity = quiche_conn_stream_capacity(_connection, stream_id);
    if (capacity > 0) {
        return make_ready_future<>();
    }
    auto inserted_promise = _writable_promises.try_emplace(stream_id, promise<>());
    return inserted_promise.first->second.get_future();
}

template <typename Socket>
void quic_connection<Socket>::send_outstanding_data_in_streams_if_possible() {
    quiche_stream_iter* iter = quiche_conn_writable(_connection);
    std::uint64_t stream_id;
    while (quiche_stream_iter_next(iter, &stream_id)) {
        auto queue_iter = _write_queues.find(stream_id);
        if (queue_iter == _write_queues.end()) {
            continue;
        }
        auto& queue = queue_iter->second;
        while (!queue.empty()) {
            auto tb = std::move(queue.front());
            queue.pop_front();

            const auto written = quiche_conn_stream_send(
                    _connection,
                    stream_id,
                    reinterpret_cast<const uint8_t*>(tb.get()),
                    tb.size(),
                    false
            );

            if (written < 0) {
                // TODO: Handle quiche error.
                fmt::print("Writing to a stream has failed with message: {}\n", written);
            }

            size_t actually_written = written > 0 ? written : 0;
            if (actually_written != tb.size()) {
                tb.trim_front(actually_written);
                queue.push_front(std::move(tb));
                break;
            }
        }

        auto stream_capacity = quiche_conn_stream_capacity(_connection, stream_id);
        if (stream_capacity > 0) {
            auto stream_promise = _writable_promises.find(stream_id);
            if (stream_promise != _writable_promises.end()) {
                stream_promise->second.set_value();
                _writable_promises.erase(stream_promise);
            }
        }
    }
    quiche_stream_iter_free(iter);
}

template <typename Socket>
future<> quic_connection<Socket>::init() {
    _timeout_timer.set_callback([this] {
        quiche_conn_on_timeout(_connection);
        (void) quic_flush();
    });

    _stream_recv_fiber = stream_recv_loop();

    // A client ought to flush after the initialization.
    return quic_flush();
}


template <typename Socket>
void quic_connection<Socket>::receive(udp_datagram&& datagram) {
    auto* fa = datagram.get_data().fragment_array();
    const quiche_recv_info recv_info = {
            .from       = &_peer_address.as_posix_sockaddr(),
            .from_len   = sizeof(_peer_address.as_posix_sockaddr()),
            .to         = &_local_address.as_posix_sockaddr(),
            .to_len     = sizeof(_local_address.as_posix_sockaddr())
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

template <typename Socket>
bool quic_connection<Socket>::is_established() {
    return quiche_conn_is_established(_connection);
}


template <typename Socket>
bool quic_connection<Socket>::is_closed() {
    return quiche_conn_is_closed(_connection);
}


// TODO: I think that this future should be resolved when stream is writable with necessary amount of bytes.
// Right now it returns when flushed and we don't do any flow control for the stream.
template <typename Socket>
[[maybe_unused]] future<> quic_connection<Socket>::write(temporary_buffer<char> tb, std::uint64_t stream_id) {

    const auto written = quiche_conn_stream_send(
            _connection,
            stream_id,
            reinterpret_cast<const uint8_t*>(tb.get()),
            tb.size(),
            false
    );

    if (written < 0) {
        // TODO: Handle quiche error.
        fmt::print("Writing to a stream has failed with message: {}\n", written);
    }

    size_t actually_written = written > 0 ? written : 0;

    if (actually_written != tb.size()) {
        tb.trim_front(actually_written);
        _write_queues.try_emplace(stream_id).first->second.push_back(std::move(tb));
    }

    (void) quic_flush();
    return wait_send_available(stream_id);
}


template <typename Socket>
[[maybe_unused]] future<temporary_buffer<char>> quic_connection<Socket>::read(std::uint64_t stream_id) {
    return _read_queues.try_emplace(stream_id, STREAM_READ_QUEUE_SIZE).first->second.pop_eventually();
}

template <typename Socket>
void quic_connection<Socket>::shutdown_input(std::uint64_t stream_id) {
    auto queue_iter = _read_queues.find(stream_id);
    if (queue_iter != _read_queues.end()) {
        _read_queues.erase(queue_iter);
    }
    if (quiche_conn_stream_shutdown(_connection, stream_id, QUICHE_SHUTDOWN_READ, 0) < 0) {
        // TODO: handle error
    }
    _input_shutdown_promises[stream_id].set_value();
    (void) quic_flush();
}

template <typename Socket>
void quic_connection<Socket>::shutdown_output(std::uint64_t stream_id) {
    // TODO: add guard to _write_queues
    // Thought: In TCP we have wait_for_all_data_acked first, do we want the same here?
    _write_queues.erase(stream_id);
    auto writable_promise = _writable_promises.find(stream_id);
    if (writable_promise != _writable_promises.end()) {
        // TODO: add custom exception
        writable_promise->second.set_exception(std::make_exception_ptr(std::runtime_error("Output has been shut down")));
        _writable_promises.erase(writable_promise);
    }
    if (quiche_conn_stream_send(_connection, stream_id, nullptr, 0, true) < 0) {
        // TODO: Handle quiche error.
    }
    if (quiche_conn_stream_shutdown(_connection, stream_id, QUICHE_SHUTDOWN_WRITE, 0)) {
        // TODO: Handle quiche error
    }
    (void) quic_flush();
}

template <typename Socket>
future<> quic_connection<Socket>::wait_input_shutdown(std::uint64_t stream_id) {
    // TODO: resolve this future wherever necessary, i.e when connection closed, stream finished (already done) and when
    // input_shutdown() called.
    return _input_shutdown_promises[stream_id].get_future();
}

template <typename Socket>
future<> quic_connection<Socket>::close() {
    if (!quiche_conn_is_closed(_connection)) {
        quiche_conn_close(_connection, 
                          true /* user closed connection */,
                          0,
                          nullptr,
                          0);
    }
    
    _closing = true;

    for (auto& [stream_id, _] : _write_queues) {
        shutdown_output(stream_id);
    }

    for (auto& [stream_id, _] : _read_queues) {
        shutdown_input(stream_id);
    }
    
    
    return quic_flush().then([this] () {
        _timeout_timer.cancel();
        _readable.set_value();
        return _stream_recv_fiber.then([this] () {
            return _socket->handle_connection_closing().then([] () {
                // _socket.release();
                return seastar::make_ready_future();
            });
        });
    });
}

template <typename Socket>
future<> quic_connection<Socket>::close(std::uint64_t stream_id) {
    // TODO: set the guard, wait for all data to be sent.
    if (quiche_conn_stream_send(_connection, stream_id, nullptr, 0, true) < 0) {
        // TODO: handle quiche error
    }
    return seastar::make_ready_future();
}

//====================
//....................
//....................
// QUIC data source
//....................
//....................
//====================


template <typename Socket>
class quiche_data_source_impl final: public data_source_impl {
private:
    lw_shared_ptr<quic_connection<Socket>> _conn;
    std::uint64_t _stream_id;

public:
    quiche_data_source_impl(lw_shared_ptr<quic_connection<Socket>> conn, std::uint64_t stream_id)
    : _conn(std::move(conn))
    , _stream_id(stream_id) 
    {}

    future<temporary_buffer<char>> get() override {
        return _conn->read(_stream_id);
    }
};


//====================
//....................
//....................
// QUIC data sink
//....................
//....................
//====================


template <typename Socket>
class quiche_data_sink_impl final: public data_sink_impl {
private:
    constexpr static size_t BUFFER_SIZE = 65'507;
    lw_shared_ptr<quic_connection<Socket>> _conn;
    std::uint64_t _stream_id;

public:
    quiche_data_sink_impl(lw_shared_ptr<quic_connection<Socket>> conn, std::uint64_t stream_id)
    : _conn(std::move(conn))
    , _stream_id(stream_id) 
    {}

    future<> put(net::packet data) override {
        return _conn->write(temporary_buffer<char>(data.fragment_array()->base, data.fragment_array()->size), _stream_id);
    }

    future<> close() override {
        // TODO: implement this by sending FIN frame to the endpoint.
        // Although, here we should wait until all data in the stream is sent - how to do it efficiently?
        return _conn->close(_stream_id);
    }

    [[nodiscard]] size_t buffer_size() const noexcept override {
        // TODO: what buffer size should be chosen? Maybe MAX_STREAM_DATA from quiche config?
        return BUFFER_SIZE;
    }
};


//====================
//....................
//....................
// QUIC connected socket
//....................
//....................
//====================


template <typename Socket>
class quiche_quic_connected_socket_impl : public quic_connected_socket_impl {
private:
    lw_shared_ptr<quic_connection<Socket>> _conn;

public:
    explicit quiche_quic_connected_socket_impl(lw_shared_ptr<quic_connection<Socket>> conn) 
    : _conn(std::move(conn)) {}

    ~quiche_quic_connected_socket_impl() {
        // For client, close the connection and destroy client socket.
        // For server, only closes the connections. The socket will be closed in some other desctructor

        (void) _conn->close();
    }

    data_source source(std::uint64_t id) override {
        return data_source(std::make_unique<quiche_data_source_impl<Socket>>(_conn, id));
    }

    data_sink sink(std::uint64_t id) override {
        // TODO: implement
        return data_sink(std::make_unique<quiche_data_sink_impl<Socket>>(_conn, id));
    }

    void shutdown_input(std::uint64_t stream_id) override {
        _conn->shutdown_input(stream_id);
    }

    void shutdown_output(std::uint64_t stream_id) override {
        _conn->shutdown_output(stream_id);
    }

    future<> wait_input_shutdown(std::uint64_t id) override {
        return _conn->wait_input_shutdown(id);
    }
    
    future<> close() override {
        return _conn->close();
    }

};


//====================
//....................
//....................
// QUIC server socket
//....................
//....................
//====================


class quic_server_socket_quiche_impl final : public quic_server_socket_impl, public seastar::weakly_referencable<quic_server_socket_quiche_impl> {
private:
    // TODO: Check the comments left in the function `quic_retry`.
    // Right now, tokens aren't used properly and passing `socket_address::length()`
    // to quiche's functions causes validation of them return false. Investigate it.
    constexpr static size_t MAX_TOKEN_SIZE =
            sizeof("quiche") - 1 + sizeof(::sockaddr_storage) + MAX_CONNECTION_ID_LENGTH;

    template<size_t Length = MAX_CONNECTION_ID_LENGTH>
    struct cid {
        uint8_t data[Length]{};
        size_t length = sizeof(data);
    };

    template<size_t TokenSize = MAX_TOKEN_SIZE>
    struct header_token {
        uint8_t data[TokenSize]{};
        size_t size = sizeof(data);
    };

    struct quic_header_info {
        uint8_t type{};
        uint32_t version{};

        cid<> scid;
        cid<> dcid;
        cid<> odcid;

        header_token<> token;
    };
    
    using server_connection_t = quic_connection<quic_server_socket_quiche_impl>;

private:
    quiche_configuration                                _quiche_configuration;
    // TODO: We can probably get rid of this flag. Check the usage.
    bool started = false;
    lw_shared_ptr<quic_udp_channel_manager>             _channel_manager;
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
    std::unordered_map<connection_id, lw_shared_ptr<server_connection_t>>  _connections;
    future<>                                            _send_queue;

public:
    explicit quic_server_socket_quiche_impl(const socket_address& sa, const std::string& cert, const std::string& key,
            const quic_connection_config& quic_config)
    : _quiche_configuration(cert, key, quic_config)
    // , _udp_channel(make_udp_channel(sa))
    , _channel_manager(make_lw_shared<quic_udp_channel_manager>(sa))
    , _buffer(MAX_DATAGRAM_SIZE)
    , _send_queue(make_ready_future<>())
    {}

    explicit quic_server_socket_quiche_impl(const std::string& cert, const std::string& key,
            const quic_connection_config& quic_config)
    : _quiche_configuration(cert, key, quic_config)
    // , _udp_channel(make_udp_channel())
    , _channel_manager(make_lw_shared<quic_udp_channel_manager>())
    , _buffer(MAX_DATAGRAM_SIZE)
    , _send_queue(make_ready_future<>())
    {}

    ~quic_server_socket_quiche_impl() override = default;

    future<> service_loop();
    future<> send(send_payload &&payload);
    void abort_accept() override;
    future<quic_accept_result> accept() override;
    socket_address local_address() const override;
    future<> handle_connection_closing();

private:
    future<> handle_datagram(udp_datagram&& datagram);
    future<> handle_post_hs_connection(const lw_shared_ptr<server_connection_t>& connection, udp_datagram&& datagram);
    // TODO: Change this function to something proper, less C-like.
    static bool validate_token(const uint8_t* token, size_t token_len, const ::sockaddr_storage* addr,
            ::socklen_t addr_len, uint8_t* odcid, size_t* odcid_len);
    // TODO: Check if we cannot provide const references here instead.
    future<> handle_pre_hs_connection(quic_header_info& header_info, udp_datagram&& datagram, connection_id& key);
    future<> negotiate_version(const quic_header_info& header_info, udp_datagram&& datagram);
    future<> quic_retry(const quic_header_info& header_info, udp_datagram&& datagram);
    static header_token<> mint_token(const quic_header_info& header_info, const ::sockaddr_storage* addr, ::socklen_t addr_len);
    connection_id generate_new_cid();
};

future<> quic_server_socket_quiche_impl::send(send_payload &&payload) {
    return _channel_manager->send(std::move(payload));
}

future<> quic_server_socket_quiche_impl::service_loop() {
    // TODO: Consider changing this to seastar::repeat and passing a stop toket to it
    // once the destructor of the class has been called.
    return keep_doing([this] {
        // TODO: Change this to something more efficient.
        // If I remember correctly, quiche has some function
        // returning an iterator over the connections that
        // have some data to send.
        for (auto& [_, connection] : _connections) {
            if (quiche_conn_is_readable(connection->_connection) && !connection->_read_future_resolved) {
                connection->_readable.set_value();
                connection->_read_future_resolved = true;
            }
            connection->send_outstanding_data_in_streams_if_possible();
        }

        return _channel_manager->read().then([this] (udp_datagram datagram) {
            return handle_datagram(std::move(datagram));
        });
    });
}

future<quic_accept_result> quic_server_socket_quiche_impl::accept() {
    if (!started) {
        _channel_manager->init();
        (void) service_loop();
        started = true;
    }
    
    promise<quic_accept_result> request;
    auto result = request.get_future();
    _accept_requests.push(std::move(request));
    return result;
}

socket_address quic_server_socket_quiche_impl::local_address() const {
    return _channel_manager->local_address();
}

future<> quic_server_socket_quiche_impl::handle_datagram(udp_datagram&& datagram) {
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

future<> quic_server_socket_quiche_impl::handle_post_hs_connection(const lw_shared_ptr<server_connection_t>& connection, 
                                                                  udp_datagram&& datagram) {
    connection->receive(std::move(datagram));
    return connection->quic_flush();
}

bool quic_server_socket_quiche_impl::validate_token(const uint8_t* token, size_t token_len,
        const ::sockaddr_storage* addr, ::socklen_t addr_len, uint8_t* odcid, size_t* odcid_len)
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

future<> quic_server_socket_quiche_impl::handle_pre_hs_connection(quic_header_info& header_info, udp_datagram&& datagram, connection_id& key) {
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

    auto [it, succeeded] = _connections.emplace(key, make_lw_shared<server_connection_t>(connection, 
                                                                                       this->weak_from_this(),
                                                                                       _channel_manager->local_address(),
                                                                                       datagram.get_src()));
    if (!succeeded) {
        fmt::print("Emplacing a connection has failed.\n");
        // TODO: Check if this can cause a double-free.
        quiche_conn_free(connection);
        return make_ready_future<>();
    }

    request.set_value(quic_accept_result {
            .connection     = quic_connected_socket(std::make_unique<quiche_quic_connected_socket_impl<quic_server_socket_quiche_impl>>(it->second)),
            .remote_address = datagram.get_src()
    });
    
    // Start the service loop in the connection.
    lw_shared_ptr<server_connection_t> &conn = it->second;
    return conn->init().then([this, datagram = std::move(datagram), &conn] () mutable {
        return handle_post_hs_connection(conn, std::move(datagram));
    });
}


future<> quic_server_socket_quiche_impl::negotiate_version(const quic_header_info& header_info, udp_datagram&& datagram) {
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
    
    return _channel_manager->send(std::move(payload));
}


future<> quic_server_socket_quiche_impl::quic_retry(const quic_header_info& header_info, udp_datagram&& datagram) {
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
    
    return _channel_manager->send(std::move(payload));
}

quic_server_socket_quiche_impl::header_token<> quic_server_socket_quiche_impl::mint_token(const quic_header_info& header_info,
        const ::sockaddr_storage* addr, const ::socklen_t addr_len)
{
    header_token<> result;

    std::memcpy(result.data, "quiche", sizeof("quiche") - 1);
    std::memcpy(result.data + sizeof("quiche") - 1, addr, addr_len);
    std::memcpy(result.data + sizeof("quiche") - 1 + addr_len, header_info.dcid.data, header_info.dcid.length);

    result.size = sizeof("quiche") - 1 + addr_len + header_info.dcid.length;

    return result;
}

connection_id quic_server_socket_quiche_impl::generate_new_cid() {
    connection_id result;

    do {
        result = connection_id::generate();
    } while (_connections.find(result) != _connections.end());

    return result;
}


future<> quic_server_socket_quiche_impl::handle_connection_closing() {
    // TODO pass cid as argument. Clean up.
    return make_ready_future<>();
}

void seastar::net::quic_server_socket_quiche_impl::abort_accept() {
    //TODO function currently used in testing, create an initial body
}


//====================
//....................
//....................
// QUIC client socket
//....................
//....................
//====================


class quic_client_socket : public weakly_referencable<quic_client_socket>, public enable_lw_shared_from_this<quic_client_socket> {
private:
    using client_connection_t = quic_connection<quic_client_socket>;
    
private:
    lw_shared_ptr<quic_udp_channel_manager> _channel_manager;
    promise<quic_connected_socket>          _connected_promise;
    quiche_configuration                    _config;
    lw_shared_ptr<client_connection_t>      _connection;
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
    future<> handle_connection_closing();

private:
    future<> receive_loop();
    future<> receive();
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

    _connection = make_lw_shared<client_connection_t>(connection_ptr, 
            this->weak_from_this(), la, sa);

    _connection->just_to_live = this->shared_from_this();

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
            _connected_promise.set_value(quic_connected_socket(
                    std::make_unique<quiche_quic_connected_socket_impl<quic_client_socket>>(_connection)));
        }

        if (quiche_conn_is_readable(_connection->_connection) && !_connection->_read_future_resolved) {
            _connection->_readable.set_value();
            _connection->_read_future_resolved = true;
        }

        _connection->send_outstanding_data_in_streams_if_possible();

        return _connection->quic_flush();
    });
}


future<> quic_client_socket::handle_connection_closing() {
    _channel_manager->abort_queues(std::make_exception_ptr(user_closed_connection_exception()));
    return _receive_fiber.handle_exception([this] (const std::exception_ptr& e) {
        return _channel_manager->close(); 
    });
}


void quiche_log_printer(const char* line, void* args) {
    std::cout << line << std::endl;
}

} // anonymous namespace

quic_server_socket quic_listen(socket_address sa, const std::string& cert_file,
        const std::string& cert_key, const quic_connection_config& quic_config)
{
    return quic_server_socket(std::make_unique<quic_server_socket_quiche_impl>(sa, cert_file, cert_key, quic_config));
}

quic_server_socket quic_listen(const std::string& cert_file, const std::string& cert_key,
        const quic_connection_config& quic_config)
{
    return quic_server_socket(std::make_unique<quic_server_socket_quiche_impl>(cert_file, cert_key, quic_config));
}

// Design:
// udp_channel_manager <=> socket <=> client_connection <=> data_sink/source (on top of quic_connected_socket)
// We can create 2 subclasses (client_socket, server_socket) with their corresponding logic. This way we can have
// one implementation for the rest of the classes.
future<quic_connected_socket> quic_connect(socket_address sa, const quic_connection_config& quic_config) {
    return seastar::do_with(make_lw_shared<quic_client_socket>(quic_config),
            [sa] (const lw_shared_ptr<quic_client_socket>& client_socket) {
        return client_socket->connect(sa);
    });
}

input_stream<char> quic_connected_socket::input(std::uint64_t id) {
    return input_stream<char>(_impl->source(id));
}

output_stream<char> quic_connected_socket::output(std::uint64_t id, size_t buffer_size) {
    output_stream_options opts;
    opts.batch_flushes = true;
    return {_impl->sink(id), buffer_size};
}

void quic_connected_socket::shutdown_input(std::uint64_t stream_id) {
    _impl->shutdown_input(stream_id);
}

void quic_connected_socket::shutdown_output(std::uint64_t stream_id) {
    _impl->shutdown_output(stream_id);
}

future<> quic_connected_socket::wait_input_shutdown(std::uint64_t stream_id) {
    return _impl->wait_input_shutdown(stream_id);
}

future<> quic_connected_socket::close() {
    return _impl->close();
}

void quic_enable_logging() {
    quiche_enable_debug_logging(quiche_log_printer, nullptr);
}

} // namespace seastar::net
