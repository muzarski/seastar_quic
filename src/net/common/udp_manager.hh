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

// Seastar features.
#include <seastar/core/future.hh>           // seastar::future
#include <seastar/core/temporary_buffer.hh> // seastar::temporary_buffer
#include <seastar/core/queue.hh>            // seastar::queue
#include <seastar/net/api.hh>               // seastar::net::udp_channel,
                                            // seastar::net::udp_datagram
#include <seastar/net/quic.hh>              // quic_byte_type
#include <seastar/net/socket_defs.hh>       // seastar::net::socket_address

namespace seastar::net {

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
    bool                _closed = false;

public:
    quic_udp_channel_manager()
    : _channel(make_udp_channel())
    , _write_fiber(make_ready_future<>())
    , _read_fiber(make_ready_future<>())
    , _write_queue(WRITE_QUEUE_SIZE) // TODO: decide on what packet qs size to use
    , _read_queue(READ_QUEUE_SIZE)
    {}

    explicit quic_udp_channel_manager(const socket_address& sa)
    : _channel(make_udp_channel(sa))
    , _write_fiber(make_ready_future<>())
    , _read_fiber(make_ready_future<>())
    , _write_queue(WRITE_QUEUE_SIZE) // TODO: decide on what packet qs size to use
    , _read_queue(READ_QUEUE_SIZE)
    {}

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
        if (_closed) {
            return make_ready_future<>();
        }

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

} // namespace seastar::net
