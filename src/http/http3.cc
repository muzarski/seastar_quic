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

#include <seastar/http/http3.hh>
#include <seastar/core/when_all.hh>
#include <seastar/core/thread.hh>

namespace seastar {

logger h3logger("http3");

namespace http3 {

void connection::on_new_connection() {
    _server._connections.push_back(*this);
}

connection::~connection() {
    _server._connections.erase(_server._connections.iterator_to(*this));
}

future<> http3_server::listen(socket_address addr, const std::string &cert_file, const std::string &cert_key,
                                  [[maybe_unused]] const net::quic_connection_config &quic_config)
{
    fmt::print("Called http3_server::listen with: {}, {}, {}", addr, cert_file, cert_key);
    _listener = net::quic_http3_listen(addr, cert_file, cert_key, quic_config);
    do_accepts();
    return make_ready_future<>();
}

void http3_server::do_accepts() {
    // Start accepting incoming connections.
    (void) try_with_gate(_task_gate, [this] () {
        return keep_doing([this] () {
            return try_with_gate(_task_gate, [this] () {
                return accept_one();
            });
        }).handle_exception_type([] (const gate_closed_exception& e) {});
    }).handle_exception_type([] (const gate_closed_exception& e) {});
}

future<> http3_server::accept_one() {
    return _listener.accept().then([this] (net::quic_http3_connected_socket&& socket) mutable {
        auto conn = std::make_unique<connection>(*this, std::move(socket));
        (void) try_with_gate(_task_gate, [conn = std::move(conn)] () mutable {
            return conn->process().handle_exception([] (const std::exception_ptr& e) {
                h3logger.debug("Connection processing error: {}", e);
            });
        }).handle_exception_type([] (const gate_closed_exception& e) {});
        return make_ready_future<>();
    }).handle_exception([] (const std::exception_ptr& e) {
        h3logger.debug("Accept error: {}", e);
    });
}

future<> http3_server::stop() {
    future<> closed = _task_gate.close();
    _listener.abort_accept();
    for (auto&& conn : _connections) {
        conn.stop();
    }
    return closed;
}

sstring http3_server_control::generate_server_name() {
    static thread_local uint16_t idgen;
    return seastar::format("http-{}", idgen++);
}

future<> http3_server_control::listen(socket_address addr, const std::string &cert_file, const std::string &cert_key,
                             const net::quic_connection_config &quic_config)
{
    return setup_alt_svc_server(addr, cert_file, cert_key).then([this, addr, cert_key, cert_file, quic_config] () {
        socket_address server_address = {addr.as_posix_sockaddr_in().sin_addr.s_addr, static_cast<uint16_t>(addr.port() + 1)};
        return _server.listen(server_address, cert_file, cert_key, quic_config);
    });
}

future<> http3_server_control::set_routes(const std::function<void(httpd::routes &)>& fun) {
    fun(_server._routes);
    return _alt_svc_server.set_routes(fun);
}

future<> http3_server_control::start(const sstring &name) {
    return _alt_svc_server.start(name);
}

future<> http3_server_control::stop() {
    return when_all(_alt_svc_server.stop(), _server.stop()).then([] (std::tuple<future<>, future<>> completed) {
        try {
            std::get<0>(completed).get();
        }
        catch (...) {
            h3logger.debug("Error during stopping the httpd service: {}", std::current_exception());
        }

        try {
            std::get<1>(completed).get();
        }
        catch (...) {
            h3logger.debug("Error during stopping the http3 service: {}", std::current_exception());
        }
        return make_ready_future<>();
    });
}

future<> http3_server_control::setup_alt_svc_server(socket_address addr, const std::string &cert_file,
                                                        const std::string &cert_key)
{
    return async([cert_file, cert_key, addr, this] () {
       seastar::shared_ptr<tls::credentials_builder> creds = seastar::make_shared<tls::credentials_builder>();
       creds->set_dh_level(tls::dh_params::level::MEDIUM);
       creds->set_x509_key_file(cert_file, cert_key, tls::x509_crt_format::PEM).get();
       creds->set_system_trust().get();
       std::cout << "set keys\n";

       _alt_svc_server.server().invoke_on_all([alt_svc_port = addr.port() + 1, creds] (httpd::http_server &server) {
           server.set_tls_credentials(creds->build_server_credentials());
           server.set_http3_alt_svc_port(static_cast<uint16_t>(alt_svc_port));
           return make_ready_future<>();
       }).get();

       _alt_svc_server.listen(addr).get();
    });
}

} // namespace http3

} // namespace seastar