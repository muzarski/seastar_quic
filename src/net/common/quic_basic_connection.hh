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

#include "quic_common.hh"
#include "seastar/net/quic.hh"

// Seastar features.
#include <seastar/core/shared_future.hh>    // seastar::shared_promise
#include <seastar/core/timer.hh>            // seastar::core::timer
#include <seastar/core/weak_ptr.hh>         // seastar::weak_ptr
#include <seastar/net/api.hh>               // seastar::net::udp_datagram
#include <seastar/net/socket_defs.hh>       // seastar::net::socket_address
#include <seastar/core/gate.hh>             // seastar::gate

// Third-party API.
#include <quiche.h>

// STD.
#include <chrono>       // Pacing.
#include <memory>       // std::destroy_at
#include <optional>
#include <queue>        // std::priority_queue
#include <stdexcept>
#include <utility>      // std::exchange
#include <vector>

namespace seastar::net {

// A basis for `connection`. Provides the following functionalities:
//   1) pacing,
//   2) sending packets after Quiche's preprocessing of data in streams,
//   3) passing data from the network to Quiche to process it
//      for specific streams.
//
// `QI` is the QUIC instance this connection type is stored by.
template<typename QI>
class quic_basic_connection {
// Local definitions.
private:
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
protected:
    using type            = quic_basic_connection<QI>;
    using instance_type   = QI;
    using connection_type = typename instance_type::connection_type;

// Local constants.
private:
    // Acceptable error when sending out packets. We use this to avoid
    // situations when the send timer needs to constantly call the callback
    // with very short breaks in between. Instead, we send everything
    // that ought to be sent within the span `[now, now + SEND_TIME_EPSILON]`.
    constexpr static send_time_duration SEND_TIME_EPSILON = std::chrono::nanoseconds(20);

// Local structures.
protected:
    class marker {
    private:
        bool _marked = false;
    public:
        constexpr void mark() noexcept { _marked = true; }
        constexpr operator bool() const noexcept { return _marked; }
    };
private:
    // Payload with a timestamp indicating when it should be sent.
    // Used for pacing.
    struct paced_payload {
    private:
        // When to send the data.
        send_time_point _time;
    public:
        // Data to be sent.
        send_payload payload;

    public:
        paced_payload(send_payload spl, const send_time_point& t)
        : _time(t), payload(std::move(spl)) {}

        // For providing the type with a total order so that
        // we can sort it.
        bool operator>(const paced_payload& other) const noexcept(noexcept(_time > other._time)) {
            return _time > other._time;
        }

        [[nodiscard]] const auto& get_time() const noexcept {
            return _time;
        }
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
        marker              _aborted;

    public:
        decltype(auto) get_shared_future() const noexcept {
            return _readable.get_shared_future();
        }

        void mark_as_ready() noexcept {
            if (!_promise_resolved && !_aborted) {
                _readable.set_value();
                _promise_resolved = true;
            }
        }

        void reset() noexcept {
            if (_promise_resolved && !_aborted) {
                _readable = shared_promise<>{};
                _promise_resolved = false;
            }
        }

        void abort() noexcept {
            if (!_aborted) {
                reset();
                _readable.set_exception(std::make_exception_ptr(quic_aborted_exception()));
                _aborted.mark();
            }
        }
    };

    // An extenstion of `std::priority_queue` to provide a means
    // to move the top element out of it.
    template<typename Elem, typename Container = std::vector<Elem>, typename Compare = std::greater<Elem>>
    class send_queue_template : public std::priority_queue<Elem, Container, Compare> {
    private:
        using super_type = std::priority_queue<Elem, Container, Compare>;

    public:
        Elem fetch_top() {
            std::pop_heap(super_type::c.begin(), super_type::c.end(), super_type::comp);
            Elem result = std::move(super_type::c.back());
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

// Fields.
protected:
    // The Quiche connection instance corresponding to a particular `quic_connection`.
    // If `_connection` is equal to `nullptr`, the connection has already been invalidated
    // and no further clean-up is needed.
    quiche_conn*                 _connection;
    weak_ptr<instance_type>      _socket;
    // TODO: Check if keeping two buffers is necessary.
    std::vector<quic_byte_type>  _buffer;
    std::vector<quic_byte_type>  _out_buffer;

    const socket_address         _peer_address;

    send_timer                   _send_timer;
    timeout_timer                _timeout_timer;

    send_queue                   _send_queue;

    read_marker                  _read_marker;
    marker                       _closing_marker;

    promise<>                    _ensure_closed_promise;
    std::optional<promise<>>     _connect_done_promise;

    quic_connection_id           _connection_id;

// Constructors + the destructor.
public:
    explicit quic_basic_connection(quiche_conn* conn, weak_ptr<instance_type> socket,
            const socket_address& pa, const quic_connection_id& id)
    : _connection(conn)
    , _socket(std::move(socket))
    , _buffer(MAX_DATAGRAM_SIZE)
    , _out_buffer(MAX_DATAGRAM_SIZE)
    , _peer_address(pa)
    , _send_timer()
    , _timeout_timer()
    , _ensure_closed_promise()
    , _connect_done_promise(std::in_place)
    , _connection_id(id) {}

    quic_basic_connection(const quic_basic_connection&) = delete;
    quic_basic_connection& operator=(const quic_basic_connection&) = delete;

    explicit quic_basic_connection(quic_basic_connection&& other) noexcept
    : _connection(std::exchange(other._connection, nullptr))
    , _socket(std::move(other._socket))
    , _buffer(std::move(other._buffer))
    , _out_buffer(std::move(other._out_buffer))
    , _peer_address(std::move(other._peer_address))
    , _send_timer(std::move(other._send_timer))
    , _timeout_timer(std::move(other._timeout_timer))
    , _send_queue(std::move(other._send_queue))
    , _read_marker(std::move(other._read_marker))
    , _closing_marker(std::move(other._closing_marker))
    , _ensure_closed_promise(std::move(other._ensure_closed_promise))
    , _connect_done_promise(std::move(other._connect_done_promise))
    , _connection_id(std::move(other._connection_id)) {}

    quic_basic_connection& operator=(quic_basic_connection&& other) noexcept {
        if (this != std::addressof(other)) {
            std::destroy_at(this);
            new (this) quic_basic_connection<QI> (std::move(other));
        }
        return *this;
    }

    ~quic_basic_connection() noexcept {
        if (_connection) {
            quiche_conn_free(std::exchange(_connection, nullptr));
        }
    }

// Public methods.
public:
    // Initializes the callbacks and loops.
    void init();

    // Pass a datagram to process by the connection.
    void receive(udp_datagram&& datagram);

    future<> abort() {
        // CRTP.
        static_assert(std::is_base_of_v<quic_basic_connection<QI>, connection_type>,
                      "Invalid connection type");
        return static_cast<connection_type*>(this)->abort();
    }

    bool is_closed() const noexcept;

    future<> quic_flush();

    future<> ensure_closed() noexcept;
    [[nodiscard]] socket_address remote_address();
    future<> connect_done();
    quic_connection_id cid();

// Protected methods.
protected:
    bool is_closing() const noexcept;
    [[nodiscard]] gate& qgate() noexcept {
        return _socket->qgate();
    }
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



template<typename QI>
void quic_basic_connection<QI>::init() {
    _send_timer.set_callback([this] {
        (void) try_with_gate(qgate(), [this] () {
            return repeat([this] {
                if (_send_queue.empty()) {
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                }

                const send_time_point now = send_clock::now();
                const send_time_point& send_time = _send_queue.top().get_time();

                if (is_closing() || send_time <= now + SEND_TIME_EPSILON) {
                    // It is time to send the packet from the front of the queue.
                    auto payload = std::move(_send_queue.fetch_top().payload);
                    return _socket->send(std::move(payload)).then([] () {
                        return make_ready_future<stop_iteration>(stop_iteration::no);
                    });
                } else {
                    // No more packets should be sent now.
                    _send_timer.rearm(send_time);
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                }
            }).handle_exception_type([] (const quic_aborted_exception& e) {});
        }).handle_exception_type([] (const gate_closed_exception& e) {});
    });

    _timeout_timer.set_callback([this] {
        // fmt::print(stderr, "\t[Quic basic connection]: timeouted.\n");
        quiche_conn_on_timeout(_connection);
        if (is_closed()) {
            qlogger.info("Calling abort from on_timeout");
            (void) abort();
            return;
        }

        (void) quic_flush();
    });

    // The client side of a connection ought to flush after initialization.
    (void) quic_flush();

    // fmt::print(stderr, "\t[Quic basic connection]: Initialized.\n");
}

template<typename QI>
void quic_basic_connection<QI>::receive(udp_datagram&& datagram) {
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
        qlogger.warn("[quic_connection::receive] Failed to process a QUIC packet. Error: {}", recv_result);
        return;
    }

    if (is_closed()) {
        qlogger.info("Calling abort from receive");
        (void) abort();
        return;
    }

    if (_connect_done_promise && quiche_conn_is_established(_connection)) {
        _connect_done_promise->set_value();
        _connect_done_promise = std::nullopt;
    }

    if (quiche_conn_is_readable(_connection)) {
        _read_marker.mark_as_ready();
    }
}

template<typename QI>
bool quic_basic_connection<QI>::is_closed() const noexcept {
    return quiche_conn_is_closed(_connection);
}

template<typename QI>
future<> quic_basic_connection<QI>::quic_flush() {
    return try_with_gate(qgate(), [this] () {
        return repeat([this] {
            // Converts a time point stored as `timespec` to `send_time_point`.
            constexpr auto get_send_time = [](const timespec& at) constexpr -> send_time_point {
                return send_time_point(
                        std::chrono::duration_cast<send_time_duration>(
                                std::chrono::seconds(at.tv_sec) + std::chrono::nanoseconds(at.tv_nsec)
                        )
                );
            };

            quiche_send_info send_info;
            const auto written = quiche_conn_send(_connection, reinterpret_cast<uint8_t *>(_out_buffer.data()), _out_buffer.size(), &send_info);

            if (written == QUICHE_ERR_DONE) {
                return make_ready_future<stop_iteration>(stop_iteration::yes);
            }

            if (written < 0) {
                qlogger.warn("[quic_basic_connection::quic_flush] failed to create a packet, error: {}", written);
                return make_ready_future<stop_iteration>(stop_iteration::no);
            }

            temporary_buffer<quic_byte_type> tb{_out_buffer.data(), static_cast<size_t>(written)};
            send_payload payload{std::move(tb), send_info.to, send_info.to_len};

            const send_time_point send_time = get_send_time(send_info.at);

            if (_closing_marker) {
                // User requested to close the connection. At this point we don't care about pacing.
                return _socket->send(std::move(payload)).then([] () {
                    return make_ready_future<stop_iteration>(stop_iteration::no);
                });
            }

            if (_send_queue.empty() || send_time < _send_queue.top().get_time()) {
                _send_timer.rearm(send_time);
            }
            _send_queue.push(paced_payload{std::move(payload), send_time});
            return make_ready_future<stop_iteration>(stop_iteration::no);
        }).then([this] {
            if (is_closed()) {
                const auto timeout = static_cast<int64_t>(quiche_conn_timeout_as_millis(_connection));
                std::cout << "Got timeout while being closed -> " << timeout << std::endl;
            }
            if (!is_closed()) {
                const auto timeout = static_cast<int64_t>(quiche_conn_timeout_as_millis(_connection));
                if (timeout >= 0) {
                    _timeout_timer.rearm(timeout_clock::now() + std::chrono::milliseconds(timeout));
                }
            }
            return make_ready_future<>();
        }).handle_exception_type([] (const quic_aborted_exception& e) {});
    }).handle_exception_type([] (const gate_closed_exception& e) {});
}

template<typename QI>
future<> quic_basic_connection<QI>::ensure_closed() noexcept {
    return _ensure_closed_promise.get_future();
}

template<typename QI>
[[nodiscard]] socket_address quic_basic_connection<QI>::remote_address() {
    return _peer_address;
}

template<typename QI>
future<> quic_basic_connection<QI>::connect_done() {
    return _connect_done_promise->get_future();
}

template<typename QI>
quic_connection_id quic_basic_connection<QI>::cid() {
    return _connection_id;
}

template<typename QI>
bool quic_basic_connection<QI>::is_closing() const noexcept {
    return quiche_conn_is_closed(_connection) || _closing_marker;
}


} // namespace seastar::net
