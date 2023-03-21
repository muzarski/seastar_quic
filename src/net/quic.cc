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
#include <seastar/core/shared_future.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/core/queue.hh>
#include <seastar/net/api.hh>
#include <seastar/net/socket_defs.hh>

#include <fmt/core.h>   // For development purposes, ditch this later on.

#include <quiche.h>

#include <algorithm>
#include <chrono>
#include <cstring>      // std::memset, etc.
#include <optional>
#include <random>       // Generating connection IDs
#include <queue>
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
    quiche_configuration(quiche_configuration& other) = delete;
    quiche_configuration& operator=(quiche_configuration &other) = delete;

    quiche_configuration(quiche_configuration&& other) noexcept
    : _config(std::exchange(other._config, nullptr))
    {}

    quiche_configuration& operator=(quiche_configuration&& other) noexcept {
        _config = std::exchange(other._config, nullptr);
        return *this;
    }

    explicit quiche_configuration(const quic_connection_config& config)
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

        constexpr auto convert_cc = [](quic_cc_algorithm cc) constexpr noexcept -> quiche_cc_algorithm {
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
        const auto handle_quiche_err = [&](auto return_code, const auto& msg) {
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


using quic_buffer = temporary_buffer<quic_byte_type>;

struct send_payload {
    quic_buffer     buffer;
    socket_address  dst;

    send_payload() = default;

    send_payload(quic_buffer&& buf, const socket_address& dest)
    : buffer(std::move(buf))
    , dst(dest)
    {}

    send_payload(quic_buffer&& buf, const ::sockaddr_storage& dest, ::socklen_t dest_len)
    : buffer(std::move(buf))
    {
        // TODO: Handle IPv6.
        ::sockaddr_in addr_in;
        std::memcpy(std::addressof(addr_in), std::addressof(dest), dest_len);
        dst = addr_in;
    }
};

class quic_udp_channel_manager {
private:
    constexpr static size_t WRITE_QUEUE_SIZE = 212'992;
    constexpr static size_t READ_QUEUE_SIZE  = 212'992;

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
        return _read_fiber.handle_exception([this] (const std::exception_ptr& e) {
            return _write_fiber.handle_exception([this] (const std::exception_ptr& e) {
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



template<typename Socket>
class quic_connection {
private:
    constexpr static size_t STREAM_READ_QUEUE_SIZE = 10'000;

    // Type of the timer responsible for timeout events.
    using timeout_timer = timer<std::chrono::steady_clock>;
    // Type of the timer responsible for sending data (pacing).
    using send_timer    = timer<std::chrono::steady_clock>;

    using timeout_clock = typename timeout_timer::clock;
    using send_clock    = typename send_timer::clock;

    using timeout_time_point    = typename timeout_timer::time_point;
    using timeout_time_duration = typename timeout_timer::duration;
    using send_time_point       = typename send_timer::time_point;
    using send_time_duration    = typename send_timer::duration;

private:
    // Acceptable error when sending out packets. We use this to avoid
    // situations when the send timer needs to constantly call the callback
    // with very short breaks in between. Instead, we send everything
    // that ought to be sent within the span `[now, now + SEND_TIME_EPSILON]`.
    constexpr static send_time_duration SEND_TIME_EPSILON = std::chrono::nanoseconds(20);

private:
    // Payload with a timestamp when the data should be send.
    // Its purpose is to cooperate with timers and provide pacing.
    struct paced_payload {
    private:
        // When to send the data.
        send_time_point time;

    public:
        // Data to be sent.
        send_payload    payload;

        paced_payload(send_payload spl, const send_time_point& t)
        : time(t)
        , payload(std::move(spl))
        {}

        // For setting an order on the type so we can sort instances of it in priority queues.
        bool operator>(const paced_payload& other) const noexcept(noexcept(time > other.time)) {
            return time > other.time;
        }

        const auto& get_time() const noexcept {
            return time;
        }
    };

    struct quic_stream {
    public:
        // Data to be read from the stream.
        queue<quic_buffer>              read_queue = queue<quic_buffer>(STREAM_READ_QUEUE_SIZE);
        // Data to be sent via the stream.
        std::deque<quic_buffer>         write_queue;
        // A field used for providing the user of the API
        // with the information when they will be able to
        // send data via the stream again (by producing
        // a `shared_future` from the `shared_promise`)
        // -- the future will only hold a value when
        // they can send data via the stream again.
        //
        // The value of the field is normally equal
        // to `std::nullopt` except when the stream
        // is cluttered and cannot accept more data,
        // in which case it holds a promise.
        std::optional<shared_promise<>> maybe_writable = std::nullopt;
        // Flag signalizing whether output has been shutdown on the stream.
        // Used as a guard for future writes.
        bool                            shutdown_output = false;
    };

    // Class providing a way to mark data if there is some data
    // to be processed by the streams.
    class read_marker {
    private:
        // A `promise<>` used for generating `future<>`s to provide
        // a means to mark if there may be some data to be processed by
        // the streams, and to check the marker.
        shared_promise<>    _readable         = shared_promise<>{};
        // Equals to `true` if and only if the promise `_readable`
        // has been assigned a value.
        bool                _promise_resolved = false;

    public:
        decltype(auto) get_shared_future() const noexcept {
            return _readable.get_shared_future();
        }

        void mark_as_ready() noexcept {
            if (!_promise_resolved) {
                _readable.set_value();
                _promise_resolved = true;
            }
        }

        void reset() noexcept {
            if (_promise_resolved) {
                _readable = shared_promise<>{};
                _promise_resolved = false;
            }
        }
    };

    // A wrapper over bool to prevent setting the value back to `false`
    // once an instance of `quic_connection` has been marked as closing.
    // Doing that could cause a lot of problems as some loops could have
    // already been stopped, but some other not. It's undefined what should
    // happen in that case, so it's better to ban it altogether.
    class closing_marker {
    private:
        bool _closing = false;

    public:
        void mark_as_closing() noexcept { _closing = true; }
        operator bool() const noexcept { return _closing; }
    };

    // An extension of `std::priority_queue` to provide a means to move an element out of it.
    template<typename T, typename Container = std::vector<T>, typename Compare = std::greater<T>>
    class send_queue_template : public std::priority_queue<T, Container, Compare> {
    public:
        T fetch_top() {
            using super_type = std::priority_queue<T, Container, Compare>;

            std::pop_heap(super_type::c.begin(), super_type::c.end(), super_type::comp);
            T result = std::move(super_type::c.back());
            super_type::c.pop_back();
            return result;
        }
    };

    // The type of the container storing packets waiting to be sent
    // to the network.
    //
    // TODO: Investigate if Quiche specifies the timestamps
    // the library gives are always order in the non-decreasing order.
    // If that's the case, replace this with something more efficient,
    // for example with `std::queue`.
    using send_queue = send_queue_template<paced_payload>;

private:
    // The Quiche connection instance corresponding to a particular `quic_connection`.
    // If `_connection` is equal to `nullptr`, the connection has already been invalidated
    // and no further clean-up is needed.
    quiche_conn*                                    _connection;
    // The socket via which communication with the network is performed.
    lw_shared_ptr<Socket>                           _socket;
    std::vector<quic_byte_type>                     _buffer;

    const socket_address                            _peer_address;

    std::unordered_map<quic_stream_id, quic_stream> _streams;

    send_timer                                      _send_timer;
    timeout_timer                                   _timeout_timer;

    // Data to be sent to the peer.
    //
    // Invariant: data is ordered in the non-decreasing order
    //            in regard to the expected time it should be sent.
    send_queue                                      _send_queue;

    future<>                                        _stream_recv_fiber;
    read_marker                                     _read_marker;

    // Set to `true` when requested by the user to be closed
    // or when the destructor has been called. Set to `false` otherwise.
    closing_marker                                  _closing_marker;

private:
    bool is_closing() const noexcept;
    future<> stream_recv_loop();
    future<> wait_send_available(quic_stream_id stream_id);

public:
    // TODO: Might be deleted later on. Right now the default constructor
    // is present to make development easier.
    quic_connection() = default;

    quic_connection(quiche_conn* connection, lw_shared_ptr<Socket> socket, const socket_address& pa)
    : _connection(connection)
    , _socket(socket)
    , _buffer(MAX_DATAGRAM_SIZE)
    , _peer_address(pa)
    , _send_timer()
    , _timeout_timer()
    , _stream_recv_fiber(make_ready_future<>())
    {}

    quic_connection(const quic_connection&) = delete;
    quic_connection& operator=(const quic_connection&) = delete;

    quic_connection(quic_connection&& other)
    : _connection(std::exchange(other._connection, nullptr))
    , _socket(other.socket)
    , _buffer(std::move(other._buffer))
    , _peer_address(other._peer_address)
    , _send_timer(std::move(other._send_timer))
    , _timeout_timer(std::move(other._timeout_timer))
    , _send_queue(std::move(other._send_queue))
    , _stream_recv_fiber(std::move(other._stream_recv_fiber))
    , _read_marker(std::move(other._read_marker))
    , _closing_marker(other._closing_marker)
    {}

    quic_connection& operator=(quic_connection&& other) {
        if (this != std::addressof(other)) {
            this->~quic_connection();
            new (this) quic_connection {std::move(other)};
        }
        return *this;
    }

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

    // Initializes the callbacks and loops.
    future<> init();

    // Pass a datagram to process by the connection.
    void receive(udp_datagram&& datagram);

    // Send a message via a stream.
    future<> write(quic_buffer qb, quic_stream_id stream_id);
    // Read a message from a stream.
    future<quic_buffer> read(quic_stream_id stream_id);

    bool is_established() const noexcept;
    bool is_closed() const noexcept;

    void send_outstanding_data_in_streams_if_possible();
    future<> quic_flush();

    void shutdown_output(quic_stream_id stream_id);

    future<> close();
};

template<typename Socket>
bool quic_connection<Socket>::is_closing() const noexcept {
    return quiche_conn_is_closed(_connection) || _closing_marker;
}

template<typename Socket>
future<> quic_connection<Socket>::stream_recv_loop() {
    return do_until([this] { return is_closing(); }, [this] {
        return _read_marker.get_shared_future().then([this] {
            quic_stream_id stream_id;
            auto iter = quiche_conn_readable(_connection);

            while (quiche_stream_iter_next(iter, &stream_id)) {
                auto& stream = _streams[stream_id];

                // TODO for danmas: think about it
                if (quiche_conn_stream_finished(_connection, stream_id)) {
                    stream.read_queue.push(temporary_buffer<char>("", 0));
                    continue;
                }

                while (quiche_conn_stream_readable(_connection, stream_id)) {
                    bool fin = false;
                    const auto recv_result = quiche_conn_stream_recv(
                        _connection,
                        stream_id,
                        reinterpret_cast<uint8_t*>(_buffer.data()),
                        _buffer.size(),
                        &fin
                    );

                    if (recv_result < 0) {
                        // TODO: Handle this properly.
                        fmt::print(stderr, "Reading from a stream has failed with message: {}\n", recv_result);
                    } else {
                        quic_buffer message{_buffer.data(), static_cast<size_t>(recv_result)};
                        // TODO: Wrap this in some kind of `not_full` future
                        // (or just read only when necessary).
                        // TODO2: Learn more about exceptions that might be thrown here.
                        stream.read_queue.push(std::move(message));
                    }
                }
            }

            quiche_stream_iter_free(iter);

            if (!quiche_conn_is_readable(_connection)) {
                _read_marker.reset();
            }

            return quic_flush();
        });
    });
}

template<typename Socket>
future<> quic_connection<Socket>::wait_send_available(quic_stream_id stream_id) {
    if (quiche_conn_stream_capacity(_connection, stream_id) > 0) {
        return make_ready_future<>();
    } else {
        auto& stream = _streams[stream_id];
        if (!stream.maybe_writable.has_value()) {
            stream.maybe_writable = shared_promise<>{};
        }
        return stream.maybe_writable->get_shared_future();
    }
}

template<typename Socket>
future<> quic_connection<Socket>::init() {
    _send_timer.set_callback([this] {
        (void) repeat([this] {
            if (_send_queue.empty()) {
                return make_ready_future<stop_iteration>(stop_iteration::yes);
            }

            const send_time_point now = send_clock::now();
            const send_time_point& send_time = _send_queue.top().get_time();

            if (send_time <= now + SEND_TIME_EPSILON) {
                // It is time to send the packet from the front of the queue.
                auto payload = std::move(_send_queue.fetch_top().payload);
                return _socket->send(std::move(payload)).then([] {
                    return make_ready_future<stop_iteration>(stop_iteration::no);
                });
            } else {
                // No more packets should be sent now.
                _send_timer.rearm(send_time);
                return make_ready_future<stop_iteration>(stop_iteration::yes);
            }
        });
    });

    _timeout_timer.set_callback([this] {
        quiche_conn_on_timeout(_connection);
        (void) quic_flush();
    });

    _stream_recv_fiber = stream_recv_loop();

    // The client side of a connection ought to flush after initialization.
    return quic_flush();
}

template<typename Socket>
void quic_connection<Socket>::receive(udp_datagram&& datagram) {
    auto* fa = datagram.get_data().fragment_array();
    auto pa = _peer_address.as_posix_sockaddr();
    auto la = _socket->local_address().as_posix_sockaddr();

    const quiche_recv_info recv_info = {
        .from       = &pa,
        .from_len   = sizeof(pa),
        .to         = &la,
        .to_len     = sizeof(la)
    };

    const auto recv_result = quiche_conn_recv(
        _connection,
        reinterpret_cast<uint8_t*>(fa->base),
        fa->size,
        &recv_info
    );

    if (recv_result < 0) {
        fmt::print(stderr, "Failed to process a QUIC packet. Return value: {}\n", recv_result);
    } else if (quiche_conn_is_readable(_connection)) {
        _read_marker.mark_as_ready();
    }
}

template<typename Socket>
[[maybe_unused]] future<> quic_connection<Socket>::write(quic_buffer qb, quic_stream_id stream_id) {
    // TODO: throw an exception if _closing_marker is set to true
    auto _stream = _streams.find(stream_id);
    if (_stream != _streams.end() && _stream->second.shutdown_output) {
        return make_exception_future<>(std::runtime_error("Output has been shutdown for a given stream.")); // TODO: custom exception?
    }

    const auto written = quiche_conn_stream_send(
        _connection,
        stream_id,
        reinterpret_cast<const uint8_t*>(qb.get()),
        qb.size(),
        false
    );

    if (written < 0) {
        // TODO: Handle the error.
        fmt::print("[Write] Writing to a stream has failed with message: {}\n", written);
    }

    if (!std::cmp_equal(written, qb.size())) {
        qb.trim_front(written);
        // TODO: Can a situation like this happen that Quiche keeps track
        // of a stream but we don't store it in the map? Investigate it.
        // In such a case, we should catch an exception here and report it.
        auto& stream = _streams[stream_id];
        stream.write_queue.push_front(std::move(qb));
    }

    return quic_flush().then([stream_id, this] () {
        return wait_send_available(stream_id);
    });
}

template<typename Socket>
future<quic_buffer> quic_connection<Socket>::read(quic_stream_id stream_id) {
    // TODO: throw an exception if _closing_marker is set to true
    auto& stream = _streams[stream_id];
    return stream.read_queue.pop_eventually();
}

template<typename Socket>
bool quic_connection<Socket>::is_established() const noexcept {
    return quiche_conn_is_established(_connection);
}

template<typename Socket>
bool quic_connection<Socket>::is_closed() const noexcept {
    return quiche_conn_is_closed(_connection);
}

template <typename Socket>
void quic_connection<Socket>::send_outstanding_data_in_streams_if_possible() {
    auto* iter = quiche_conn_writable(_connection);
    quic_stream_id stream_id;

    while (quiche_stream_iter_next(iter, &stream_id)) {
        auto& stream = _streams[stream_id];
        auto& queue = stream.write_queue;

        while (!queue.empty()) {
            auto qb = std::move(queue.front());
            queue.pop_front();

            const auto written = quiche_conn_stream_send(
                    _connection,
                    stream_id,
                    reinterpret_cast<const uint8_t*>(qb.get()),
                    qb.size(),
                    false
            );

            if (written < 0) {
                // TODO: Handle quiche error.
                fmt::print("[Send outstanding] Writing to a stream has failed with message: {}\n", written);
            }

            if (!std::cmp_equal(written, qb.size())) {
                qb.trim_front(static_cast<size_t>(written));
                queue.push_front(std::move(qb));
                break;
            }
        }

        if (quiche_conn_stream_capacity(_connection, stream_id) > 0) {
            if (stream.maybe_writable) {
                stream.maybe_writable->set_value();
                stream.maybe_writable = std::nullopt;
            }
        }
    }
    quiche_stream_iter_free(iter);
}

template<typename Socket>
future<> quic_connection<Socket>::quic_flush() {
    // TODO: Why not use `_buffer` instead?
    static uint8_t out[MAX_DATAGRAM_SIZE];

    return repeat([this] {
        // Converts a time point stored as `timespec` to `send_time_point`.
        constexpr auto get_send_time = [](const timespec& at) constexpr -> send_time_point {
            // TODO: Ditch modulo here when the library has fixed the issue with `timespec`.
            // See: `https://github.com/cloudflare/quiche/pull/1403`.
            using nsec_type = decltype(at.tv_nsec);
            return send_time_point(
                std::chrono::duration_cast<send_time_duration>(
                    std::chrono::seconds(at.tv_sec) + std::chrono::nanoseconds(at.tv_nsec % static_cast<nsec_type>(1e9))
                )
            );
        };

        quiche_send_info send_info;
        const auto written = quiche_conn_send(_connection, out, sizeof(out), &send_info);

        if (written == QUICHE_ERR_DONE) {
            return make_ready_future<stop_iteration>(stop_iteration::yes);
        }

        if (written < 0) {
            throw std::runtime_error("Failed to create a packet.");
        }

        quic_buffer qb{reinterpret_cast<quic_byte_type*>(out), static_cast<size_t>(written)};
        send_payload payload{std::move(qb), send_info.to, send_info.to_len};

        const send_time_point send_time = get_send_time(send_info.at);

        if (_send_queue.empty() || send_time < _send_queue.top().get_time()) {
            _send_timer.rearm(send_time);
        }
        _send_queue.push(paced_payload{std::move(payload), send_time});

        return make_ready_future<stop_iteration>(stop_iteration::no);
    }).then([this] {
        const auto timeout = static_cast<std::int64_t>(quiche_conn_timeout_as_millis(_connection));
        if (timeout >= 0) {
            _timeout_timer.rearm(timeout_clock::now() + std::chrono::milliseconds(timeout));
        }
        return make_ready_future<>();
    });
}

template<typename Socket>
void quic_connection<Socket>::shutdown_output(quic_stream_id stream_id) {
    auto& stream = _streams[stream_id];

    stream.write_queue.clear();
    stream.shutdown_output = true;
    stream.maybe_writable->set_exception(std::runtime_error("Output has been shutdown on the given stream."));
    stream.maybe_writable = std::nullopt;

    if (quiche_conn_stream_send(_connection, stream_id, nullptr, 0, true) < 0) {
        throw std::runtime_error("Unexpected quiche_conn_stream_send error");
    }
    if (quiche_conn_stream_shutdown(_connection, stream_id, QUICHE_SHUTDOWN_WRITE, 0)) {
        throw std::runtime_error("Unexpected quiche_conn_stream_shutdown error");
    }

    (void) quic_flush();
}

template<typename Socket>
future<> quic_connection<Socket>::close() {
    // TODO: Wait until stream capacity is MAX.
    // Wait until paced_payload_queue is empty.

    if (!quiche_conn_is_closed(_connection)) {
        quiche_conn_close(
            _connection,
            true, // The user closed the connection.
            0,
            nullptr,
            0
        );
    }

    _closing_marker.mark_as_closing();

    return quic_flush().then([this] {
        _timeout_timer.cancel();
        _read_marker.mark_as_ready();

        return _stream_recv_fiber.then([this] {
            return _socket->handle_connection_closing().then([this] {
                _socket.release();
            });
        });
    });
}


//====================
//....................
//....................
// QUIC data source
//....................
//....................
//====================


template<typename Socket>
class quiche_data_source_impl final : public data_source_impl {
private:
    lw_shared_ptr<quic_connection<Socket>>  _connection;
    quic_stream_id                          _stream_id;

public:
    quiche_data_source_impl(lw_shared_ptr<quic_connection<Socket>> connection, quic_stream_id stream_id)
    : _connection(std::move(connection))
    , _stream_id(stream_id)
    {}

    future<quic_buffer> get() override {
        return _connection->read(_stream_id);
    }
};


//====================
//....................
//....................
// QUIC data sink
//....................
//....................
//====================


template<typename Socket>
class quiche_data_sink_impl final: public data_sink_impl {
private:
    constexpr static size_t BUFFER_SIZE = 65'507;

private:
    lw_shared_ptr<quic_connection<Socket>>  _connection;
    quic_stream_id                          _stream_id;

public:
    quiche_data_sink_impl(lw_shared_ptr<quic_connection<Socket>> connection, quic_stream_id stream_id)
    : _connection(std::move(connection))
    , _stream_id(stream_id)
    {}

    future<> put(net::packet data) override {
        const auto* fa = data.fragment_array();
        quic_buffer qb{reinterpret_cast<quic_byte_type*>(fa->base), static_cast<size_t>(fa->size)};

        return _connection->write(std::move(qb), _stream_id);
    }

    future<> close() override {
        // TODO: implement this by sending FIN frame to the endpoint.
        // Although, here we should wait until all data in the stream is sent - how to do it efficiently?
        return seastar::make_ready_future();
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


template<typename Socket>
class quiche_quic_connected_socket_impl : public quic_connected_socket_impl {
private:
    lw_shared_ptr<quic_connection<Socket>> _connection;

public:
    explicit quiche_quic_connected_socket_impl(lw_shared_ptr<quic_connection<Socket>> connection)
    : _connection(std::move(connection))
    {}

    data_source source(quic_stream_id stream_id) override {
        return data_source(std::make_unique<quiche_data_source_impl<Socket>>(_connection, stream_id));
    }

    data_sink sink(quic_stream_id stream_id) override {
        // TODO: implement
        return data_sink(std::make_unique<quiche_data_sink_impl<Socket>>(_connection, stream_id));
    }

    void shutdown_output(quic_stream_id stream_id) override {
        return _connection->shutdown_output(stream_id);
    }

    future<> close() override {
        return _connection->close();
    }

};


//====================
//....................
//....................
// QUIC server socket
//....................
//....................
//====================


class quic_server_socket_quiche_impl final
        : public quic_server_socket_impl
        , public enable_lw_shared_from_this<quic_server_socket_quiche_impl>
{
private:
    // TODO: Check the comments left in the function `quic_retry`.
    // Right now, tokens aren't used properly and passing `socket_address::length()`
    // to quiche's functions causes validation of them return false. Investigate it.
    constexpr static size_t MAX_TOKEN_SIZE =
            sizeof("quiche") - 1 + sizeof(::sockaddr_storage) + MAX_CONNECTION_ID_LENGTH;

    template<size_t Length = MAX_CONNECTION_ID_LENGTH>
    struct cid_template {
        constexpr static size_t CID_MAX_LENGTH = Length;

        uint8_t data[Length];
        size_t  length = sizeof(data);
    };

    template<size_t TokenSize = MAX_TOKEN_SIZE>
    struct header_token_template {
        constexpr static size_t HEADER_TOKEN_MAX_SIZE = TokenSize;

        uint8_t data[TokenSize];
        size_t  size = sizeof(data);
    };

    using cid          = cid_template<>;
    using header_token = header_token_template<>;

    struct quic_header_info {
        uint8_t type;
        uint32_t version;

        cid scid;
        cid dcid;
        cid odcid;

        header_token token;
    };

    using server_connection = quic_connection<quic_server_socket_quiche_impl>;

private:
    quiche_configuration                                _quiche_configuration;
    // TODO: We can probably get rid of this flag. Check the usage.
    bool started = false;
    lw_shared_ptr<quic_udp_channel_manager>             _channel_manager;
    // Local buffer for receiving bytes from the network.
    // Use std::vector instead of an automatic memory container
    // to avoid stack overflows.
    std::vector<quic_byte_type>                         _buffer;
    std::queue<promise<quic_accept_result>>             _accept_requests;
    // TODO: Consider using std::map or std::vector instead. Pros:
    //       * no need to provide a hashing function
    //       * might be faster for fewer connections
    // Best if we could use std::colony (C++23) or some equivalent of it.
    std::unordered_map<connection_id, lw_shared_ptr<server_connection>>  _connections;
    future<>                                            _send_queue;

public:
    explicit quic_server_socket_quiche_impl(const socket_address& sa, const std::string& cert, const std::string& key,
            const quic_connection_config& quic_config)
    : _quiche_configuration(cert, key, quic_config)
    , _channel_manager(make_lw_shared<quic_udp_channel_manager>(sa))
    , _buffer(MAX_DATAGRAM_SIZE)
    , _send_queue(make_ready_future<>())
    {}

    explicit quic_server_socket_quiche_impl(const std::string& cert, const std::string& key,
            const quic_connection_config& quic_config)
    : _quiche_configuration(cert, key, quic_config)
    , _channel_manager(make_lw_shared<quic_udp_channel_manager>())
    , _buffer(MAX_DATAGRAM_SIZE)
    , _send_queue(make_ready_future<>())
    {}

    ~quic_server_socket_quiche_impl() override = default;

    future<> service_loop();
    future<> send(send_payload &&payload);
    future<quic_accept_result> accept() override;
    socket_address local_address() const override;
    future<> handle_connection_closing();

private:
    future<> handle_datagram(udp_datagram&& datagram);
    future<> handle_post_hs_connection(const lw_shared_ptr<server_connection>& connection, udp_datagram&& datagram);
    // TODO: Change this function to something proper, less C-like.
    static bool validate_token(const uint8_t* token, size_t token_len, const ::sockaddr_storage* addr,
            ::socklen_t addr_len, uint8_t* odcid, size_t* odcid_len);
    // TODO: Check if we cannot provide const references here instead.
    future<> handle_pre_hs_connection(quic_header_info& header_info, udp_datagram&& datagram, connection_id& key);
    future<> negotiate_version(const quic_header_info& header_info, udp_datagram&& datagram);
    future<> quic_retry(const quic_header_info& header_info, udp_datagram&& datagram);
    static header_token mint_token(const quic_header_info& header_info, const ::sockaddr_storage* addr, ::socklen_t addr_len);
    connection_id generate_new_cid();
};

future<> quic_server_socket_quiche_impl::send(send_payload &&payload) {
    return _channel_manager->send(std::move(payload));
}

future<> quic_server_socket_quiche_impl::service_loop() {
    // TODO: Consider changing this to seastar::repeat and passing a stop toket to it
    // once the destructor of the class has been called.
    return keep_doing([this] {
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

future<> quic_server_socket_quiche_impl::handle_post_hs_connection(const lw_shared_ptr<server_connection>& connection,
        udp_datagram&& datagram)
{
    connection->receive(std::move(datagram));
    connection->send_outstanding_data_in_streams_if_possible();
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

future<> quic_server_socket_quiche_impl::handle_pre_hs_connection(quic_header_info& header_info, udp_datagram&& datagram,
        connection_id& key)
{
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

    auto [it, succeeded] = _connections.emplace(
        key,
        make_lw_shared<server_connection>(
            connection,
            this->shared_from_this(),
            datagram.get_src()
        )
    );

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
    // TODO: If the reference is removed, a segmentation fault occurs.
    lw_shared_ptr<server_connection>& conn = it->second;
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

    quic_buffer qb{reinterpret_cast<quic_byte_type*>(_buffer.data()), static_cast<size_t>(written)};
    send_payload payload{std::move(qb), datagram.get_src()};

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

    quic_buffer qb{reinterpret_cast<quic_byte_type*>(_buffer.data()), static_cast<size_t>(written)};
    send_payload payload(std::move(qb), datagram.get_src());

    return _channel_manager->send(std::move(payload));
}

quic_server_socket_quiche_impl::header_token quic_server_socket_quiche_impl::mint_token(const quic_header_info& header_info,
        const ::sockaddr_storage* addr, const ::socklen_t addr_len)
{
    header_token result;

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


//====================
//....................
//....................
// QUIC client socket
//....................
//....................
//====================


class quic_client_socket : public enable_lw_shared_from_this<quic_client_socket> {
private:
    using client_connection = quic_connection<quic_client_socket>;

private:
    lw_shared_ptr<quic_udp_channel_manager> _channel_manager;
    promise<quic_connected_socket>          _connected_promise;
    quiche_configuration                    _config;
    lw_shared_ptr<client_connection>        _connection;
    future<>                                _receive_fiber;
    bool                                    _promise_resolved;

private:
    future<> receive_loop();
    future<> receive();

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

    [[nodiscard]] socket_address local_address() const {
        return _channel_manager->local_address();
    }
};

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

        _connection->send_outstanding_data_in_streams_if_possible();

        return _connection->quic_flush();
    });
}

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

    _connection = make_lw_shared<client_connection>(connection_ptr, this->shared_from_this(), sa);

    // TODO: Something must clean this up afterwards, most likely `quic_connected_socket`.
    _receive_fiber = receive_loop();

    return _connection->init().then([this] {
        return _connected_promise.get_future();
    });
}

future<> quic_client_socket::send(send_payload&& payload) {
    return _channel_manager->send(std::move(payload));
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

input_stream<quic_byte_type> quic_connected_socket::input(quic_stream_id id) {
    return input_stream<quic_byte_type>(_impl->source(id));
}

output_stream<quic_byte_type> quic_connected_socket::output(quic_stream_id id, size_t buffer_size) {
    output_stream_options opts;
    opts.batch_flushes = true;
    return {_impl->sink(id), buffer_size};
}

void quic_connected_socket::shutdown_output(quic_stream_id id) {
    return _impl->shutdown_output(id);
}

future<> quic_connected_socket::close() {
    return _impl->close();
}

void quic_enable_logging() {
    quiche_enable_debug_logging(quiche_log_printer, nullptr);
}

} // namespace seastar::net
