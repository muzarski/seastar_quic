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
#include <seastar/core/when_all.hh>
#include <seastar/net/quic.hh>              // quic_byte_type
#include <seastar/net/socket_defs.hh>       // seastar::net::socket_address

namespace seastar::net {

class quic_udp_channel_manager {
private:
    constexpr static size_t WRITE_QUEUE_SIZE = 212'992;
    constexpr static size_t READ_QUEUE_SIZE  = 212'992;

private:
    udp_channel         _channel;
    queue<send_payload> _write_queue;
    queue<udp_datagram> _read_queue;
    std::optional<promise<>> _flushed_promise;

public:
    quic_udp_channel_manager()
    : _channel(make_udp_channel())
    , _write_queue(WRITE_QUEUE_SIZE)
    , _read_queue(READ_QUEUE_SIZE)
    {}

    explicit quic_udp_channel_manager(const socket_address& sa)
    : _channel(make_udp_channel(sa))
    , _write_queue(WRITE_QUEUE_SIZE)
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
    future<> run() {
        return when_all(read_loop(), write_loop()).then([this] (std::tuple<future<>, future<>> joined) {
            try {
                qlogger.info("[udp_channel_manager] read_loop finished");
                std::get<0>(joined).get();
            } catch (const quic_aborted_exception& ex) {

            } catch (const std::system_error& ex) {
                if (ex.code().value() != ECONNABORTED) {
                    qlogger.warn("[quic_udp_channel_manager::run]: Unexpected error during read_loop() {}",
                                 std::current_exception());
                }
            } catch (...) {
                qlogger.warn("[quic_udp_channel_manager::run]: Unexpected error during read_loop() {}",
                             std::current_exception());
            }

            try {
                qlogger.info("[udp_channel_manager] write_loop finished");
                std::get<1>(joined).get();
            } catch (const quic_aborted_exception& ex) {

            } catch (...) {
                qlogger.warn("[quic_udp_channel_manager::run]: Unexpected error during write_loop() {}",
                             std::current_exception());
            }

            _channel.close();
            return make_ready_future<>();
        });
    }
    future<> flush_write_queue() {
        if (_write_queue.empty()) {
            return make_ready_future<>();
        }

        _flushed_promise = promise<>();
        return _flushed_promise->get_future();
    }
    void abort_read_queue() {
        _channel.shutdown_input();
        _read_queue.abort(std::make_exception_ptr(quic_aborted_exception()));
    }
    void abort_write_queue() {
        _write_queue.abort(std::make_exception_ptr(quic_aborted_exception()));
    }
    void abort_queues() {
        abort_read_queue();
        abort_write_queue();
    }

private:
    future<> read_loop() {
        return keep_doing([this] () {
            return _channel.receive().then([this] (udp_datagram datagram) {
                return _read_queue.push_eventually(std::move(datagram));
            });
        });
    }

    future<> write_loop() {
        return keep_doing([this] () {
            return _write_queue.pop_eventually().then([this] (send_payload payload) {
                return _channel.send(payload.dst, std::move(payload.buffer)).then([this] () {
                    if (_flushed_promise && _write_queue.empty()) {
                        _flushed_promise->set_value();
                    }
                });
            });
        });
    }
};

} // namespace seastar::net
