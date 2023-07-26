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
/*
 * Copyright 2015 Cloudius Systems
 */

#pragma once

#include <seastar/http/httpd.hh>
#include <seastar/net/quic.hh>
#include <seastar/http/routes.hh>

namespace seastar {

namespace net {

struct quic_h3_request {
    int64_t _stream_id = 0;
    std::unique_ptr<http::request> _req;

    quic_h3_request() = default;

    explicit quic_h3_request(int64_t stream_id)
    : _stream_id(stream_id)
    , _req(std::make_unique<http::request>()) {}

    quic_h3_request(const quic_h3_request& other) = delete;
    quic_h3_request& operator=(const quic_h3_request& other) = delete;

    quic_h3_request(quic_h3_request&& other) = default;
    quic_h3_request& operator=(quic_h3_request&& other) = default;
};

struct quic_h3_reply {
    int64_t _stream_id;
    std::unique_ptr<http::reply> _resp;
    std::optional<sstring> _status_code = std::nullopt;
};

class quic_h3_connected_socket_impl {
public:
    virtual ~quic_h3_connected_socket_impl() {}
    virtual future<std::unique_ptr<quic_h3_request>> read() = 0;
    virtual future<> write(std::unique_ptr<quic_h3_reply> reply) = 0;
    virtual future<> abort() = 0;
};

class quic_h3_connected_socket {
private:
    std::unique_ptr<quic_h3_connected_socket_impl> _impl;

public:
    quic_h3_connected_socket(std::unique_ptr<quic_h3_connected_socket_impl> impl) noexcept : _impl(std::move(impl)) {}

    future<std::unique_ptr<quic_h3_request>> read();
    future<> write(std::unique_ptr<quic_h3_reply> reply);
    future<> abort();
};

struct quic_h3_accept_result {
    quic_h3_connected_socket connection;
    socket_address remote_address;
};

class quic_h3_server_socket_impl {
public:
    virtual ~quic_h3_server_socket_impl() {}
    virtual future<quic_h3_accept_result> accept() = 0;
    virtual socket_address local_address() const = 0;
    virtual void abort_accept() noexcept = 0;
};

class quic_h3_server_socket {
private:
    std::unique_ptr<quic_h3_server_socket_impl> _impl;

public:
    quic_h3_server_socket() noexcept = default;
    explicit quic_h3_server_socket(std::unique_ptr<quic_h3_server_socket_impl> impl) noexcept
            : _impl(std::move(impl)) {}
    quic_h3_server_socket(quic_h3_server_socket&& qss) noexcept = default;
    quic_h3_server_socket & operator=(quic_h3_server_socket&& qss) noexcept = default;

    ~quic_h3_server_socket() noexcept = default;

    future<quic_h3_accept_result> accept() {
        return _impl->accept();
    }

    [[nodiscard]] socket_address local_address() const noexcept {
        return _impl->local_address();
    }

    void abort_accept() noexcept {
        _impl->abort_accept();
    }
};

quic_h3_server_socket quic_h3_listen(const socket_address &sa, const std::string_view cert_file,
                                     const std::string_view cert_key, const quic_connection_config& quic_config = quic_connection_config());

} // namespace net

namespace http3 {

class http3_server;

class connection : public boost::intrusive::list_base_hook<> {
private:
    http3_server& _server;
    net::quic_h3_connected_socket _socket;
    queue<std::unique_ptr<seastar::net::quic_h3_reply>> _replies { 10 };
    std::unique_ptr<seastar::net::quic_h3_reply> _resp;
    bool _done = false;

private:
    void on_new_connection();

public:
    connection(http3_server &server, net::quic_h3_connected_socket &&socket)
    : _server(server)
    , _socket(std::move(socket)) {
        on_new_connection();
    };

    ~connection();

    future<> process();
    future<> read();
    future<> read_one();
    future<> respond();
    future<> do_response_loop();
    void set_headers(seastar::net::quic_h3_reply& resp);
    future<> start_response();
    future<bool> generate_reply(std::unique_ptr<seastar::net::quic_h3_request> req);
    future<> stop();
};

class http3_server {
private:
    friend class http3_server_control;
    friend class connection;

private:
    net::quic_h3_server_socket _listener;
    httpd::routes _routes;
    gate _task_gate;
    boost::intrusive::list<connection> _connections;

private:
    void do_accepts();
    future<> accept_one();

public:
    future<> listen(socket_address addr, const std::string& cert_file, const std::string& cert_key,
                    const net::quic_connection_config& quic_config);
    future<> stop();
};

class http3_server_control {
private:
    httpd::http_server_control _alt_svc_server;
    http3_server _server;

private:
    static sstring generate_server_name();

    future<> setup_alt_svc_server(socket_address addr, const std::string& cert_file, const std::string& cert_key);
public:
    http3_server_control()
    : _alt_svc_server()
    , _server() {}

    future<> start(const sstring& name = generate_server_name());
    future<> stop();
    future<> set_routes(const std::function<void(httpd::routes& r)>& fun);
    future<> listen(socket_address addr, const std::string& cert_file, const std::string& cert_key,
                    const net::quic_connection_config& quic_config = net::quic_connection_config());
};

} // namespace http3

} // namespace seastar

