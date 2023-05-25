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

#include "../net/common/quic_basic_connection.hh"
#include "../net/common/quic_engine.hh"
#include "../net/common/quic_server_instance.hh"

namespace seastar {

logger h3logger("http3");

namespace net {
namespace {

template<typename QI>
class h3_connection final
        : public quic_basic_connection<QI>
        , public enable_lw_shared_from_this<h3_connection<QI>>
{
// Constants.
private:
    constexpr static size_t H3_READ_QUEUE_SIZE = 10'000;
// Local definitions.
public:
    using type          = h3_connection<QI>;
    using instance_type = QI;
private:
    using super_type    = quic_basic_connection<QI>;
// Quiche HTTP3 specific fields.
private:
    quiche_h3_config* h3_config = nullptr;
    quiche_h3_conn* h3_conn = nullptr;

    static int for_each_header(uint8_t *name, size_t name_len,
                               uint8_t *value, size_t value_len,
                               void *argp) {

        // FIXME: There's a bug.
        auto *request_in_callback = static_cast<seastar::net::quic_h3_request*>(argp);
        request_in_callback->_req._headers[to_sstring(name)] = to_sstring(value); // TODO check if to_sstring actually works
        fprintf(stderr, "got HTTP header: %.*s=%.*s\n",
                (int) name_len, name, (int) value_len, value);
        return 0;
    }
// Local structures
private:
    class read_marker {
    private:
        // A `promise<>` used for generating `future<>`s to provide
        // a means to mark if there may be some data to be processed and to check the marker.
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

// Fields.
protected:
    future<> _stream_recv_fiber;
public:
    // Data to be read from the stream.
    queue< std::unique_ptr<quic_h3_request>> read_queue = queue< std::unique_ptr<quic_h3_request>>(H3_READ_QUEUE_SIZE);
    // Data to be sent via the stream.
    // std::deque<quic_buffer>         write_queue; TODO: implement buffering (not only quic_buffer, but also headers!)

// Constructors + the destructor.
public:
    template<typename... Args>
    h3_connection(Args&&... args)
    : super_type(std::forward<Args>(args)...)
    , _stream_recv_fiber(seastar::make_ready_future<>())
    {
        this->_socket->register_connection(this->shared_from_this());
        init();
    }

    ~h3_connection() = default;

// Public methods.
public:
    void init();
    void close();
    future<std::unique_ptr<quic_h3_request>> read();
    future<> write(std::unique_ptr<quic_h3_reply> reply);
    void send_outstanding_data_in_streams_if_possible();
// Private methods.
    future<> h3_recv_loop();
    // future<> wait_send_available(); TODO: buffering
};

template<typename QI>
void h3_connection<QI>::close() {
    // TODO
}

template<typename QI>
future<std::unique_ptr<quic_h3_request>> h3_connection<QI>::read() {
    // TODO
    return make_ready_future<std::unique_ptr<quic_h3_request>>();
}

template<typename QI>
future<> h3_connection<QI>::write(std::unique_ptr<quic_h3_reply> reply) {
    // TODO
}

using h3_server            = quic_server_instance<h3_connection>;
using h3_server_connection = quic_basic_connection<h3_server>;

using h3_engine = quic_engine<h3_server>;

} // anonymous namespace
} // namespace net

namespace http3 {

void connection::on_new_connection() {
    _server._connections.push_back(*this);
}

connection::~connection() {
    _server._connections.erase(_server._connections.iterator_to(*this));
}

future<> connection::process() {
    return when_all(read(), respond()).then([] (std::tuple<future<>, future<>> joined) {
        try {
            std::get<0>(joined).get();
        } catch (...) {
            h3logger.debug("Read exception encountered: {}", std::current_exception());
        }
        try {
            std::get<1>(joined).get();
        } catch (...) {
            h3logger.debug("Response exception encountered: {}", std::current_exception());
        }
        return make_ready_future<>();
    });
}


future<> connection::read() {
    return do_until([this] {return _done;}, [this] {
        return read_one();
    }).then_wrapped([this] (future<> f) {
        f.ignore_ready_future();
        return _replies.push_eventually({});
    });
}

future<> connection::read_one() {
    return _socket.read().then([this](std::unique_ptr<seastar::net::quic_h3_request> req) {
        if (!req) {
            _done = true;
            return make_ready_future<>();
        }
        req->_req.protocol_name = "https";

        sstring length_header = req->_req.get_header("Content-Length");
        req->_req.content_length = strtol(length_header.c_str(), nullptr, 10);

        auto maybe_reply_continue = [this, req = std::move(req)]() mutable {
            if (http::request::case_insensitive_cmp()(req->_req.get_header("Expect"), "100-continue")) {
                return _replies.not_full().then([req = std::move(req), this]() mutable {
                    auto continue_reply = std::make_unique<seastar::net::quic_h3_reply>();
                    set_headers(*continue_reply);
                    continue_reply->_resp.set_version(req->_req._version);
                    continue_reply->_resp.set_status(http::reply::status_type::continue_).done();
                    this->_replies.push(std::move(continue_reply));
                    return make_ready_future<std::unique_ptr<seastar::net::quic_h3_request>>(std::move(req));
                });
            } else {
                return make_ready_future<std::unique_ptr<seastar::net::quic_h3_request>>(std::move(req));
            }
        };
        return maybe_reply_continue().then([this] (std::unique_ptr<seastar::net::quic_h3_request> req) {
            return _replies.not_full().then([this, req = std::move(req)] () mutable {
                return generate_reply(std::move(req));
            }).then([this](bool done) {
                _done = done;
                return seastar::make_ready_future<>();
            });
        });
    });
}

future<bool> connection::generate_reply(std::unique_ptr<seastar::net::quic_h3_request> req) {
    auto resp = std::make_unique<seastar::net::quic_h3_reply>();
    resp->_resp.set_version(req->_req._version);
    set_headers(*resp);
    bool keep_alive = req->_req.should_keep_alive();
    if (keep_alive) {
        resp->_resp._headers["Connection"] = "Keep-Alive";
    }

    sstring url = req->_req.parse_query_param();
    sstring version = req->_req._version;
    return _server._routes.handle(url, std::unique_ptr<http::request>(&req->_req), std::unique_ptr<http::reply>(&resp->_resp)).
            then([this, keep_alive , version = std::move(version), stream_id = req->_stream_id](std::unique_ptr<http::reply> rep) {
        rep->set_version(version).done();
        auto reply = std::make_unique<seastar::net::quic_h3_reply>();
        reply->_resp = std::move(*rep);
        reply->_stream_id = stream_id;
        _replies.push(std::move(reply));
        return make_ready_future<bool>(!keep_alive);
    });
}

void connection::set_headers(seastar::net::quic_h3_reply& resp) {
    resp._resp._headers["Server"] = "Seastar httpd3";
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
    _resp->_resp._headers["Content-Length"] = to_sstring(
            _resp->_resp._content.size());
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
    (void) try_with_gate(_task_gate, [this] () {
        return keep_doing([this] () {
            return try_with_gate(_task_gate, [this] () {
                return accept_one();
            });
        }).handle_exception_type([] (const gate_closed_exception& e) {});
    }).handle_exception_type([] (const gate_closed_exception& e) {});
}

future<> http3_server::accept_one() {
    return _listener.accept().then([this] (net::quic_h3_accept_result&& result) mutable {
        auto conn = std::make_unique<connection>(*this, std::move(result.connection));
        (void) try_with_gate(_task_gate, [conn = std::move(conn)] () mutable {
            return conn->process().handle_exception([] (const std::exception_ptr& e) {
                h3logger.debug("Connection processing error: {}", e);
            });
        }).handle_exception_type([] (const gate_closed_exception& e) {
            h3logger.debug("Gate closed.");
        });
        return make_ready_future<>();
    }).handle_exception([] (const std::exception_ptr& e) {
        h3logger.debug("Accept error: {}", e);
    });
}

future<> http3_server::stop() {
    future<> closed = _task_gate.close();
    _listener.abort_accept();
    for (auto&& conn : _connections) {
        // conn.stop(); TODO: implement stop
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