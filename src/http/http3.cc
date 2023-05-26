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


// To implement here.
#include <seastar/http/http3.hh>

// Basic definitions.
#include "../net/common/quic_basic_connection.hh"
#include "../net/common/quic_engine.hh"
#include "../net/common/quic_server_instance.hh"

// Seastar features.
#include <seastar/core/when_all.hh>
#include <seastar/core/thread.hh>

// Third-party API.
#include <quiche.h>


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
    quiche_h3_config* _h3_config = nullptr;
    quiche_h3_conn*   _h3_conn   = nullptr;

// Fields.
private:
    future<>         _stream_recv_fiber;
    shared_promise<> _h3_connect_done_promise{};
    std::vector<quic_byte_type> _buffer;
public:
    // Data to be read from the stream.
    queue<std::unique_ptr<quic_h3_request>> read_queue = queue<std::unique_ptr<quic_h3_request>>(H3_READ_QUEUE_SIZE);
    // Data to be sent via the stream.
    // std::deque<quic_buffer>         write_queue; TODO: implement buffering (not only quic_buffer, but also headers!)

// Constructors + the destructor.
public:
    template<typename... Args>
    h3_connection(Args&&... args)
    : super_type(std::forward<Args>(args)...)
    , _stream_recv_fiber(seastar::make_ready_future<>())
    , _buffer(MAX_DATAGRAM_SIZE)
    {
        this->_socket->register_connection(this->shared_from_this());
    }

    ~h3_connection() = default;

// Public methods.
public:
    void init();
    void close();
    future<std::unique_ptr<quic_h3_request>> read();
    future<> write(std::unique_ptr<quic_h3_reply> reply);
    void send_outstanding_data_in_streams_if_possible();
    future<> h3_connect_done();
// Private methods.
private:
    future<> h3_recv_loop();
    // future<> wait_send_available(); TODO: buffering
};

template<typename QI>
void h3_connection<QI>::init() {
    super_type::init();

    _h3_config = quiche_h3_config_new();
    if (!_h3_config) {
        throw std::runtime_error("Could not initialize config");
    }

    _stream_recv_fiber = this->connect_done().then([this] {
        _h3_conn = quiche_h3_conn_new_with_transport(this->_connection, _h3_config);
        if (!_h3_conn) {
            throw std::runtime_error("Could not create HTTP3 connection.");
        }

        _h3_connect_done_promise.set_value();
        return this->quic_flush();
    }).then([this] {
        return h3_recv_loop();
    });
}

template<typename QI>
void h3_connection<QI>::close() {
    if (this->_closing_marker) {
        return;
    }
    this->_closing_marker.mark();

    if (!quiche_conn_is_closed(this->_connection)) {
        quiche_conn_close(
                this->_connection,
                true, // The user closed the connection.
                0,
                nullptr,
                0
        );
    }
    // TODO: handle HTTP3 close
}

template<typename QI>
void h3_connection<QI>::send_outstanding_data_in_streams_if_possible() {
    // TODO: buffering
}

template<typename QI>
future<std::unique_ptr<quic_h3_request>> h3_connection<QI>::read() {
    return read_queue.pop_eventually();
}

template<typename QI>
future<> h3_connection<QI>::write(std::unique_ptr<quic_h3_reply> reply) {
    if (this->_closing_marker) {
        return make_exception_future<>(std::runtime_error("The connection has been closed."));
    }

    std::vector<quiche_h3_header> headers;

    // TODO: get status from Seastar handler
    quiche_h3_header status = {
            .name      = reinterpret_cast<const uint8_t*>(":status"),
            .name_len  = sizeof(":status") - 1,
            .value     = reinterpret_cast<const uint8_t *>("200"),
            .value_len = sizeof("200") - 1
    };
    headers.push_back(status);

    for (const auto& h : reply->_resp->_headers) {
        headers.push_back({
            .name      = reinterpret_cast<const uint8_t*>(h.first.c_str()),
            .name_len  = h.first.size(),
            .value     = reinterpret_cast<const uint8_t*>(h.second.c_str()),
            .value_len = h.second.size(),
        });
    }

    // TODO: check result
    quiche_h3_send_response(
            _h3_conn,
            this->_connection,
            reply->_stream_id,
            headers.data(),
            headers.size(),
            false
    );

    // TODO: check result
    quiche_h3_send_body(
            _h3_conn,
            this->_connection,
            reply->_stream_id,
            reinterpret_cast<uint8_t*>(reply->_resp->_content.data()),
            reply->_resp->content_length,
            true
    );

        // TODO: buffering
//        if (written != reply->_resp->content_length) {
//
//        }

    return this->quic_flush();
}

[[maybe_unused]] // Unnecessary, but Clang complains.
int for_each_header(uint8_t *name, size_t name_len, uint8_t *value, size_t value_len, void *argp) {
    auto* request_in_callback = static_cast<quic_h3_request*>(argp);

    const auto* cname = reinterpret_cast<const char*>(name);
    const auto* cvalue = reinterpret_cast<const char*>(value);

    auto key = sstring(cname, name_len);
    auto val = sstring(cvalue, value_len);

    request_in_callback->_req->_headers[std::move(key)] = std::move(val);
    return 0;
}

template <typename QI>
future<> h3_connection<QI>::h3_recv_loop() {
    return do_until([this] { return this->is_closing(); }, [this] {
        return this->_read_marker.get_shared_future().then([this] {
            if (quiche_conn_is_established(this->_connection)) {
                if (_h3_conn == nullptr) {
                    throw std::runtime_error("Invalid state");
                }

                quiche_h3_event* ev;

                auto s = quiche_h3_conn_poll(_h3_conn, this->_connection, &ev);
                if (s < 0) {
                    std::cout << "poll res: " << s << std::endl;
                    return make_ready_future<>();
                }

                auto new_req = std::make_unique<quic_h3_request>();
                new_req->_req       = std::make_unique<http::request>();
                new_req->_stream_id = s;

                switch (quiche_h3_event_type(ev)) {
                    case QUICHE_H3_EVENT_HEADERS: {
                        const auto rc = quiche_h3_event_for_each_header(ev, for_each_header, new_req.get());
                        new_req->_req->_url     = new_req->_req->_headers[":path"];
                        new_req->_req->_method  = new_req->_req->_headers[":method"];
                        new_req->_req->_version = new_req->_req->_headers[":scheme"];

                        if (rc != 0) {
                            fmt::print(stderr, "failed to process headers\n");
                        }
                        read_queue.push(std::move(new_req));
                        break;
                    }

                    case QUICHE_H3_EVENT_DATA: {
                        const auto len = quiche_h3_recv_body(
                                _h3_conn,
                                this->_connection,
                                s,
                                reinterpret_cast<uint8_t*>(_buffer.data()),
                                _buffer.size());

                        if (len <= 0) {
                            break;
                        }

                        new_req->_req->content        = sstring(_buffer.data(), len);
                        new_req->_req->content_length = len;
                        read_queue.push(std::move(new_req));
                        break;
                    }

                    case QUICHE_H3_EVENT_FINISHED:
                    case QUICHE_H3_EVENT_RESET:
                    case QUICHE_H3_EVENT_PRIORITY_UPDATE:
                    case QUICHE_H3_EVENT_DATAGRAM:
                    case QUICHE_H3_EVENT_GOAWAY:
                        break;
                }

                quiche_h3_event_free(ev);
            }

            return make_ready_future<>();
        }).then([this] {
            if (!quiche_conn_is_readable(this->_connection)) {
                this->_read_marker.reset();
            }
            return this->quic_flush();
        });
    });
}

template <typename QI>
future<> h3_connection<QI>::h3_connect_done() {
    return _h3_connect_done_promise.get_shared_future();
}

using h3_server            = quic_server_instance<h3_connection>;
using h3_server_connection = h3_connection<h3_server>;

using h3_engine = quic_engine<h3_server>;

lw_shared_ptr<h3_server> h3_listen(const socket_address& sa, const std::string_view cert_file,
        const std::string_view cert_key, const quic_connection_config& quic_config,
        const size_t queue_length = 100)
{
    auto instance = make_lw_shared<h3_server>(sa, cert_file, cert_key, quic_config, queue_length);
    instance->init();
    h3_engine::register_instance(sa, instance);
    return instance;
}

template<typename ConnectionT>
class h3_connected_socket_impl : public quic_h3_connected_socket_impl {
// Local definitions.
public:
    using connection_type = ConnectionT;

// Fields.
private:
    lw_shared_ptr<connection_type> _connection;

// Constructors + the destructor.
public:
    explicit h3_connected_socket_impl(lw_shared_ptr<connection_type> conn) noexcept
    : _connection(conn) {}

    ~h3_connected_socket_impl() noexcept {
        std::cout << "h3 socket impl DELETING" << std::endl;
        _connection->close();
    }

// Public methods.
public:
    future<std::unique_ptr<quic_h3_request>> read() {
        return _connection->read();
    }
    future<> write(std::unique_ptr<quic_h3_reply> reply) {
        return _connection->write(std::move(reply));
    }
};

class quiche_h3_server_socket_impl final : public quic_h3_server_socket_impl {
// Local definitions.
private:
    using implementation_type = h3_connected_socket_impl<h3_server_connection>;

// Fields.
private:
    lw_shared_ptr<h3_server> _listener;

// Constructors + the destructor.
public:
    quiche_h3_server_socket_impl(const socket_address& sa, const std::string_view cert_file,
            const std::string_view cert_key, const quic_connection_config& quic_config)
    : _listener(h3_listen(sa, cert_file, cert_key, quic_config)) {}
    ~quiche_h3_server_socket_impl() = default;

// Implementation.
public:
    future<quic_h3_accept_result> accept() override {
        return _listener->accept().then([] (lw_shared_ptr<h3_server_connection> conn) {
            future<> h3_connected = conn->h3_connect_done();

            return h3_connected.then([conn = std::move(conn)] {
                auto impl = std::make_unique<implementation_type>(conn);

                return make_ready_future<quic_h3_accept_result>(quic_h3_accept_result {
                        .connection     = quic_h3_connected_socket(std::move(impl)),
                        .remote_address = conn->remote_address()
                });
            });
        });
    }

    void abort_accept() noexcept override {
        _listener->abort_accept();
    }

    [[nodiscard]] socket_address local_address() const override {
        return _listener->local_address();
    }
};

} // anonymous namespace

quic_h3_server_socket quic_h3_listen(const socket_address &sa, const std::string_view cert_file,
        const std::string_view cert_key, const quic_connection_config& quic_config)
{
    return quic_h3_server_socket(std::make_unique<quiche_h3_server_socket_impl>(
            sa, cert_file, cert_key, quic_config));
}

future<std::unique_ptr<quic_h3_request>> quic_h3_connected_socket:: read() {
    return future<std::unique_ptr<quic_h3_request>>(_impl->read());
}

future<> quic_h3_connected_socket::write(std::unique_ptr<quic_h3_reply> reply) {
    return future<>(_impl->write(std::move(reply)));
}

} // namespace net

namespace http3 {

void connection::on_new_connection() {
    _server._connections.push_back(*this);
}

connection::~connection() {
    _server._connections.erase(_server._connections.iterator_to(*this));
}

future<> connection::process() {
    h3logger.info("ABOUT TO PROCESS");
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

        auto method = req->_req->_method;

        req->_req->protocol_name = "https";

        sstring length_header = req->_req->get_header("Content-Length");
        req->_req->content_length = strtol(length_header.c_str(), nullptr, 10);

        auto maybe_reply_continue = [this, req = std::move(req)]() mutable {
            if (http::request::case_insensitive_cmp()(req->_req->get_header("Expect"), "100-continue")) {
                return _replies.not_full().then([req = std::move(req), this]() mutable {
                    auto continue_reply = std::make_unique<seastar::net::quic_h3_reply>();
                    set_headers(*continue_reply);
                    continue_reply->_resp->set_version(req->_req->_version);
                    continue_reply->_resp->set_status(http::reply::status_type::continue_).done();
                    continue_reply->_stream_id = req->_stream_id;
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
    resp->_resp = std::make_unique<http::reply>();
    resp->_resp->set_version(req->_req->_version);
    resp->_stream_id = req->_stream_id;
    set_headers(*resp);
    bool keep_alive = req->_req->should_keep_alive();
    if (keep_alive) {
        resp->_resp->_headers["Connection"] = "Keep-Alive";
    }

    sstring url = req->_req->parse_query_param();
    sstring version = req->_req->_version;
    auto http_req = std::move(req->_req);
    auto http_rep = std::move(resp->_resp);

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
    (void) try_with_gate(_task_gate, [this] () {
        return keep_doing([this] () {
            return try_with_gate(_task_gate, [this] () {
                return accept_one();
            });
        }).handle_exception_type([] (const gate_closed_exception& e) {});
    }).handle_exception_type([] (const gate_closed_exception& e) {});
}

future<> http3_server::accept_one() {
    return _listener.accept().then([this] (net::quic_h3_accept_result result) mutable {
        h3logger.info("ACCEPTED");
        auto conn = std::make_unique<connection>(*this, std::move(result.connection));
        (void) try_with_gate(_task_gate, [conn = std::move(conn)] () mutable {
            return conn->process().handle_exception([conn = std::move(conn)] (const std::exception_ptr& e) {
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
    // TODO: implement stop
//    for (auto&& conn : _connections) {
//        // conn.stop();
//    }
    return closed;
}

sstring http3_server_control::generate_server_name() {
    static thread_local uint16_t idgen;
    return seastar::format("http-{}", idgen++);
}

future<> http3_server_control::listen(socket_address addr, const std::string &cert_file,
        const std::string &cert_key, const net::quic_connection_config &quic_config)
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
        } catch (...) {
            h3logger.debug("Error during stopping the httpd service: {}", std::current_exception());
        }

        try {
            std::get<1>(completed).get();
        } catch (...) {
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
