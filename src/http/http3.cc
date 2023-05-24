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
#include <seastar/net/quic.hh>

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

    h3logger.info("Destructor of connection called.");
    _server._connections.erase(_server._connections.iterator_to(*this));
}

future<> connection::process() {
    h3logger.info("Connection accepted, about to process.");

    return when_all(read(), respond()).then([] (std::tuple<future<>, future<>> joined) {
        try {
            // std::cout << "got connection process - processing read" << std::endl;
            std::get<0>(joined).get();

        } catch (...) {
            // std::cout << "Read exception encountered" << std::endl;

            h3logger.info("Read exception encountered: {}", std::current_exception());
        }
        // std::cout << "got connection process - processed read" << std::endl;
        try {
            std::get<1>(joined).get();

        } catch (...) {
            // std::cout << "Response exception encountered" << std::endl;

            h3logger.info("Response exception encountered: {}", std::current_exception());
        }
        // std::cout << "got connection process - processed respond" << std::endl;

        // std::cout << "got connection process - processed all" << std::endl;
        h3logger.info("Finished processing.");
        return make_ready_future<>();
    });
}


future<> connection::read() {
    h3logger.info("Starting reading.");
    return do_until([this] {return _done;}, [this] {
        return read_one();
    }).then_wrapped([this] (future<> f) {
        // std::cout << "entering read - do unitl finished" << std::endl;
        f.ignore_ready_future();
        return _replies.push_eventually({});
    });
}

future<> connection::read_one() {
    // std::cout << "entering connection::read_one" << std::endl;

    return _socket.read().then([this](std::unique_ptr<seastar::net::quic_h3_request> req) {
        if (!req) {
            _done = true;
            return make_ready_future<>();
        }


        auto method = req->_req->_method;
        h3logger.info("Reading HTTP3 request, method: {}", method);

        req->_req->protocol_name = "https";

        sstring length_header = req->_req->get_header("Content-Length");
        req->_req->content_length = strtol(length_header.c_str(), nullptr, 10);

        auto maybe_reply_continue = [this, req = std::move(req)]() mutable {
            if (http::request::case_insensitive_cmp()(req->_req->get_header("Expect"), "100-continue")) {
                // std::cout << "got expect - 100 continue in read_one" << std::endl;
                return _replies.not_full().then([req = std::move(req), this]() mutable {
                    auto continue_reply = std::make_unique<seastar::net::quic_h3_reply>();
                    set_headers(*continue_reply);
                    continue_reply->_resp->set_version(req->_req->_version);
                    continue_reply->_resp->set_status(http::reply::status_type::continue_).done();
                    this->_replies.push(std::move(continue_reply));
                    return make_ready_future<std::unique_ptr<seastar::net::quic_h3_request>>(std::move(req));
                });
            } else {
                return make_ready_future<std::unique_ptr<seastar::net::quic_h3_request>>(std::move(req));
            }
        };
        // std::cout << "maybe reply from read_one" << std::endl;
        return maybe_reply_continue().then([this] (std::unique_ptr<seastar::net::quic_h3_request> req) {
            return _replies.not_full().then([this, req = std::move(req)] () mutable {
                // std::cout << "generating reply in read_one" << std::endl;
                h3logger.info("About to generate reply");
                return generate_reply(std::move(req));
            }).then([this](bool done) {
                _done = done;
                // std::cout << "read_one is done" << std::endl;
                return seastar::make_ready_future<>();
            });
        });
    });
}

future<bool> connection::generate_reply(std::unique_ptr<seastar::net::quic_h3_request> req) {
    auto resp = std::make_unique<seastar::net::quic_h3_reply>();
    resp->_resp = std::make_unique<http::reply>();
    resp->_resp->set_version(req->_req->_version);
    set_headers(*resp);
    bool keep_alive = req->_req->should_keep_alive();
    if (keep_alive) {
        resp->_resp->_headers["Connection"] = "Keep-Alive";
    }

    sstring url = req->_req->parse_query_param();
    sstring version = req->_req->_version;
    auto http_req = std::move(req->_req);
    auto http_rep = std::move(resp->_resp);

    std::cout << "DEBUG METHOD: " << http_req->_method << std::endl;
    std::cout << "DEBUG URL: " << http_req->_url << std::endl;
    std::cout << "DEBUG version: " << http_req->_version << std::endl;

    return _server._routes.handle(url, std::move(http_req), std::move(http_rep)).
            then([this, keep_alive , version = std::move(version), resp = std::move(resp)](std::unique_ptr<http::reply> rep) {
        rep->set_version(version).done();
        auto new_reply = std::make_unique<seastar::net::quic_h3_reply>();
        new_reply->_stream_id = resp->_stream_id;
        new_reply->_resp = std::move(rep);
        _replies.push(std::move(new_reply));
        return make_ready_future<bool>(!keep_alive);
    });

}

void connection::set_headers(seastar::net::quic_h3_reply& resp) {
    resp._resp->_headers["Server"] = "Seastar httpd3";
}

future<> connection::respond() {
    return do_response_loop().then_wrapped([] (future<> f) {
        f.ignore_ready_future();
        return seastar::make_ready_future();
    });
}

future<> connection::do_response_loop() {
    return _replies.pop_eventually().then([this] (std::unique_ptr<seastar::net::quic_h3_reply> reply) {
        if (!reply) {
            return make_ready_future<>();
        }
        _resp = std::move(reply);
        return start_response().then([this] {
            return do_response_loop();
        });
    });
}

future<> connection::start_response() {
    set_headers(*_resp);
    _resp->_resp->_headers["Content-Length"] = to_sstring(
            _resp->_resp->_content.size());
    _resp->_resp->content_length = _resp->_resp->_content.size();
    return _socket.write(std::move(_resp));
}

future<> http3_server::listen(socket_address addr, const std::string &cert_file, const std::string &cert_key,
                                  [[maybe_unused]] const net::quic_connection_config &quic_config)
{
    fmt::print("Called http3_server::listen with: {}, {}, {}", addr, cert_file, cert_key);
    _listener = net::quic_h3_listen(addr, cert_file, cert_key, quic_config);
    do_accepts();
    return make_ready_future<>();
}

void http3_server::do_accepts() {
    // Start accepting incoming connections.
    // std::cout << "do accepts" << std::endl;

    (void) try_with_gate(_task_gate, [this] () {
        return keep_doing([this] () {
            return try_with_gate(_task_gate, [this] () {
                // std::cout << "in do accepts" << std::endl;

                return accept_one();
            });
        }).handle_exception_type([] (const gate_closed_exception& e) {
            // std::cout << "got error in do_accepts 1" << std::endl;

        });
    }).handle_exception_type([] (const gate_closed_exception& e) {
        // std::cout << "got error in do_accepts 2" << std::endl;

    });
}

future<> http3_server::accept_one() {
    return _listener.accept().then([this] (net::quic_h3_accept_result result) mutable {
        auto conn = std::make_unique<connection>(*this, std::move(result.connection));
        (void) try_with_gate(_task_gate, [conn = std::move(conn)] () mutable {
            return conn->process().handle_exception([conn = std::move(conn)] (const std::exception_ptr& e) {
                h3logger.debug("Connection processing error: {}", e);
            }).then([] {
                h3logger.info("Finished processing.");
            });
        }).handle_exception_type([] (const gate_closed_exception& e) {
            h3logger.error("Gate already closed");
        });
        return make_ready_future<>();
    }).handle_exception([] (const std::exception_ptr& e) {
        // std::cout << "got accept_one other error: " <<  e << std::endl;

        h3logger.debug("Accept error: {}", e);
    }).then([] {
       h3logger.info("Finished handling accept.");
    });
}

future<> http3_server::stop() {
    // std::cout << "http4_server stopping" << std::endl;
    future<> closed = _task_gate.close();
    _listener.abort_accept();
    // TODO: implement close in http3 connection
//    for (auto&& conn : _connections) {
//        conn.close();
//    }
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
    // std::cout << "Seastar HTTP server start1" << std::endl;
    return _alt_svc_server.start(name);
}

future<> http3_server_control::stop() {
    // std::cout << "http3_server_control stopping" << std::endl;

    return when_all(_alt_svc_server.stop(), _server.stop()).then([] (std::tuple<future<>, future<>> completed) {
        try {
            std::get<0>(completed).get();
        }
        catch (...) {
            // std::cout << "Error during stopping the httpd service: " <<  std::current_exception() << std::endl;

            h3logger.debug("Error during stopping the httpd service: {}", std::current_exception());
        }

        try {
            std::get<1>(completed).get();
        }
        catch (...) {
            // std::cout << "Error during stopping the httpd service2: " <<  std::current_exception() << std::endl;
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
       // std::cout << "set keys\n";

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