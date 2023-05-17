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

// For dawmd to make it clearer what kind of API should be exposed by the quic-http3 backend.

struct quic_h3_request {
    int64_t _stream_id;
    http::request _req;
};

struct quic_h3_reply {
    int64_t _stream_id;
    http::reply _resp;
};

class quic_http3_connected_socket {
private:
    // quic_http3_connected_socket will probably wrap some connection class which exposes quic backend API.
    class quic_http3_connection;
    std::shared_ptr<quic_http3_connection> _conn;

public:
    future<std::unique_ptr<quic_h3_request>> read(); // return _conn->read();
    future<> write(std::unique_ptr<quic_h3_reply> reply); // return _conn->write(reply);
};

class http3_listener {
private:
    // http3_listener may as well wrap some backend listener if it's necessary
    class quic_http3_listener;
    shared_ptr<quic_http3_listener> _l;
public:
    future<quic_http3_connected_socket> accept(); // return _l->accept();
    void abort_accept() noexcept;
};

// This would start the quic-h3 server instance under the hood and return the listener.
http3_listener quic_http3_listen(socket_address addr, const std::string& cert_file, const std::string& cert_key,
                                 const net::quic_connection_config& quic_config);

} // namespace net

namespace http3 {

class http3_server;

class connection {
private:
    http3_server& _server;
    net::quic_http3_connected_socket _socket;

private:
    void on_new_connection();

public:
    connection(http3_server &server, net::quic_http3_connected_socket &&socket)
    : _server(server)
    , _socket(std::move(socket)) {
        on_new_connection();
    };

    ~connection();

    future<> process();
    void stop();
};

class http3_server {
private:
    friend class http3_server_control;
    friend class connection;

private:
    net::http3_listener _listener;
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

