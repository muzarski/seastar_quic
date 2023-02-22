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

#include <seastar/core/seastar.hh>
#include <seastar/core/iostream.hh>

#include <cstddef>

namespace seastar::net {

// Congestion control algorithm
enum class quic_cc_algorithm {
    RENO,
    CUBIC,
    BBR
};

struct quic_connection_config {
    uint64_t            max_idle_timeout                    =      5'000;
    size_t              max_datagram_size                   =     65'507;
    size_t              max_recv_udp_payload_size           =     65'507;
    size_t              max_send_udp_payload_size           =     65'507;
    uint64_t            initial_max_data                    = 10'000'000;
    uint64_t            initial_max_stream_data_bidi_local  =  1'000'000;
    uint64_t            initial_max_stream_data_bidi_remote =  1'000'000;
    uint64_t            initial_max_stream_data_uni         =  1'000'000;
    uint64_t            initial_max_streams_bidi            =      1'000;
    uint64_t            initial_max_streams_uni             =      1'000;
    bool                disable_active_migration            =      false;
    quic_cc_algorithm   congestion_control_algorithm        = quic_cc_algorithm::RENO;
    uint64_t            max_stream_window                   = 16'000'000;
    uint64_t            max_connection_window               = 24'000'000;
};

class quic_connected_socket_impl {
public:
    virtual ~quic_connected_socket_impl() {}
    virtual data_source source(std::uint64_t id) = 0;
    virtual data_sink sink(std::uint64_t id) = 0;
    virtual void shutdown_input(std::uint64_t id) = 0;
    virtual void shutdown_output(std::uint64_t id) = 0;
    virtual future<> wait_input_shutdown(std::uint64_t id) = 0;
    virtual future<> close() = 0;
};

class quic_connected_socket {
private:
    std::unique_ptr<quic_connected_socket_impl> _impl;

public:
    explicit quic_connected_socket(std::unique_ptr<quic_connected_socket_impl> impl) noexcept : _impl(std::move(impl)) {}
    input_stream<char> input(std::uint64_t id);
    output_stream<char> output(std::uint64_t id, size_t buffer_size = 8192);
    void shutdown_input(std::uint64_t id);
    void shutdown_output(std::uint64_t id);
    future<> wait_input_shutdown(std::uint64_t id);
    future<> close();
};

struct quic_accept_result {
    quic_connected_socket connection;
    socket_address remote_address;
};

class quic_server_socket_impl {
public:
    virtual ~quic_server_socket_impl() {}
    virtual future<quic_accept_result> accept() = 0;
    virtual socket_address local_address() const = 0;
};

class quic_server_socket {
private:
    std::unique_ptr<quic_server_socket_impl> _impl;

public:
    quic_server_socket() noexcept = default;
    explicit quic_server_socket(std::unique_ptr<quic_server_socket_impl> impl) noexcept
    : _impl(std::move(impl)) {}
    quic_server_socket(quic_server_socket&& qss) noexcept = default;
    ~quic_server_socket() noexcept = default;

    future<quic_accept_result> accept() {
        return _impl->accept();
    }

    [[nodiscard]] socket_address local_address() const noexcept {
        return _impl->local_address();
    }
};

// Initiate the quic server, provide certs, choose version etc.
quic_server_socket quic_listen(const std::string& cert_file, const std::string& cert_key,
                               const quic_connection_config& quic_config = quic_connection_config());

quic_server_socket quic_listen(socket_address sa, const std::string& cert_file, const std::string& cert_key,
                               const quic_connection_config& quic_config = quic_connection_config());

// Initiate connection to the server, choose version etc.
future<quic_connected_socket> 
quic_connect(socket_address sa, const quic_connection_config& quic_config = quic_connection_config());

// Quiche raw logs
void quic_enable_logging();

} // namespace seastar::net
