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
    std::unique_ptr<connection> _current_conn; // TODO: IT'S WRONG, ONLY FOR TESTING PURPOSES!

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
    , _server() {
        std::cout << "Seastar HTTP3 server" << std::endl;
    }

    future<> start(const sstring& name = generate_server_name());
    future<> stop();
    future<> set_routes(const std::function<void(httpd::routes& r)>& fun);
    future<> listen(socket_address addr, const std::string& cert_file, const std::string& cert_key,
                    const net::quic_connection_config& quic_config = net::quic_connection_config());
};

} // namespace http3

} // namespace seastar

