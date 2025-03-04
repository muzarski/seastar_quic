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
#include <seastar/core/future.hh>
#include <seastar/core/thread.hh>
#include <seastar/core/when_all.hh>

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

    struct h3_buffered_reply {
        std::unique_ptr<quic_h3_reply> reply;
        size_t body_iter = 0;
        bool written_headers = false;
    };

    struct h3_stream {
        h3_buffered_reply buffered_reply{};
        std::optional<shared_promise<>> maybe_writable = std::nullopt;
    };

// Quiche HTTP3 specific fields.
private:
    quiche_h3_config* _h3_config = nullptr;
    quiche_h3_conn*   _h3_conn   = nullptr;

// Fields.
private:
    future<>         _stream_recv_fiber;
    shared_promise<> _h3_connect_done_promise{};
    std::vector<quic_byte_type> _buffer;

    // Requests that are not FINISHED yet.
    std::unordered_map<int64_t, quic_h3_request> _requests;
    std::unordered_map<int64_t, h3_stream> _streams;
    bool _aborted = false;
public:
    // Data to be read from the stream.
    queue<std::unique_ptr<quic_h3_request>> _read_queue = queue<std::unique_ptr<quic_h3_request>>(H3_READ_QUEUE_SIZE);

// Constructors + the destructor.
public:
    template<typename... Args>
    h3_connection(Args&&... args)
    : super_type(std::forward<Args>(args)...)
    , _stream_recv_fiber(seastar::make_ready_future<>())
    , _buffer(MAX_DATAGRAM_SIZE)
    , _requests()
    {
        this->_socket->register_connection(this->shared_from_this());
    }

    ~h3_connection() = default;

// Public methods.
public:
    void init();
    void close();
    future<> abort();
    future<std::unique_ptr<quic_h3_request>> read();
    future<> write(std::unique_ptr<quic_h3_reply> reply);
    void send_outstanding_data_in_streams_if_possible();
    future<> h3_connect_done();
// Private methods.
private:
    static std::vector<quiche_h3_header> to_quiche_headers(const std::unique_ptr<quic_h3_reply>& reply);
    future<> h3_recv_loop();
    future<> do_h3_poll();
    future<> wait_send_available(h3_stream& stream);
};

template<typename QI>
void h3_connection<QI>::init() {
    super_type::init();

    _h3_config = quiche_h3_config_new();
    if (!_h3_config) {
        throw std::runtime_error("Could not initialize config");
    }

    (void) this->connect_done().then([this] {
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
future<> h3_connection<QI>::abort() {
    if (_aborted) {
        return make_ready_future<>();
    }
    _aborted = true;
    this->_read_marker.abort();
    _read_queue.abort(std::make_exception_ptr(quic_aborted_exception()));
    for (auto &[stream_id, s] : _streams) {
        if (s.maybe_writable) {
            s.maybe_writable->set_exception(std::make_exception_ptr(quic_aborted_exception()));
        }
    }

    this->_timeout_timer.cancel();
    this->_send_timer.cancel();
    return make_ready_future<>();
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
                (uint8_t*) "",
                0
        );
    }
    // TODO: handle HTTP3 close
}

template<typename QI>
std::vector<quiche_h3_header> h3_connection<QI>::to_quiche_headers(const std::unique_ptr<quic_h3_reply> &reply) {
    // TODO get status header from seastar handler
    std::vector<quiche_h3_header> headers;
//    if (!reply->_status_code) {
//        reply->_status_code = to_sstring(reply->_resp->_status);
//    }

//reply->_status_code->c_str()
//reply->_status_code->size()
    quiche_h3_header status = {
            .name      = reinterpret_cast<const uint8_t*>(":status"),
            .name_len  = sizeof(":status") - 1,
            .value     = reinterpret_cast<const uint8_t *>("200"),
            .value_len = sizeof("200") - 1,
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

    return headers;
}

template<typename QI>
void h3_connection<QI>::send_outstanding_data_in_streams_if_possible() {
    auto* iter = quiche_conn_writable(this->_connection);
    quic_stream_id stream_id;
    int header_res;
    ssize_t body_res;
    size_t body_written, to_write;

    while (quiche_stream_iter_next(iter, &stream_id)) {
        auto& stream = _streams[stream_id];
        auto& buffered_reply = stream.buffered_reply;

        if (!stream.maybe_writable) {
            continue;
        }

        if (!buffered_reply.written_headers) {
            auto headers = to_quiche_headers(buffered_reply.reply);

            header_res = quiche_h3_send_response(
                    _h3_conn,
                    this->_connection,
                    stream_id,
                    headers.data(),
                    headers.size(),
                    buffered_reply.reply->_resp->_content.empty()
            );

            // Write the headers.
            if (header_res == QUICHE_H3_ERR_STREAM_BLOCKED) {
                stream.buffered_reply.written_headers = false;
                continue;
            }
            else if (header_res < 0) {
                h3logger.warn("Unexpected error during quiche_h3_send_response: {}", header_res);
                continue;
            }

            buffered_reply.written_headers = true;
        }

        body_written = buffered_reply.body_iter;
        to_write = buffered_reply.reply->_resp->_content.size();

        body_res = quiche_h3_send_body(
                _h3_conn,
                this->_connection,
                stream_id,
                reinterpret_cast<uint8_t*>(buffered_reply.reply->_resp->_content.data() + body_written),
                buffered_reply.reply->_resp->content_length - body_written,
                true
        );
        if (body_res < -1) {
            h3logger.warn("[h3_connection::write]: writing reply body to stream ({}) has failed with error: {}.",
                          stream_id, body_res);
        }

        body_written = body_res < 0 ? 0 : static_cast<size_t>(body_res);
        stream.buffered_reply.body_iter += body_written;

        if (stream.buffered_reply.body_iter >= to_write && stream.maybe_writable) {
            stream.maybe_writable->set_value();
            stream.maybe_writable = std::nullopt;
            stream.buffered_reply.reply.reset();
        }
    }
    quiche_stream_iter_free(iter);
}

template<typename QI>
future<std::unique_ptr<quic_h3_request>> h3_connection<QI>::read() {
    return _read_queue.pop_eventually();
}

template<typename QI>
future<> h3_connection<QI>::wait_send_available(h3_stream& stream) {
    size_t written = stream.buffered_reply.body_iter;
    size_t to_write = stream.buffered_reply.reply->_resp->_content.size();

    if (stream.buffered_reply.written_headers && written == to_write) {
        return make_ready_future<>();
    }

    if (!stream.maybe_writable) {
        stream.maybe_writable = shared_promise<>();
    }
    return stream.maybe_writable->get_shared_future();
}

template<typename QI>
future<> h3_connection<QI>::write(std::unique_ptr<quic_h3_reply> reply) {
    if (this->_closing_marker) {
        return make_exception_future<>(std::runtime_error("The connection has been closed."));
    }

    int64_t stream_id = reply->_stream_id;
    int header_res;
    ssize_t body_res;
    size_t body_written;
    h3_stream &stream = _streams[stream_id];
    stream.buffered_reply.written_headers = true;
    stream.buffered_reply.body_iter = 0;
    auto headers = to_quiche_headers(reply);

    header_res = quiche_h3_send_response(
            _h3_conn,
            this->_connection,
            reply->_stream_id,
            headers.data(),
            headers.size(),
            reply->_resp->_content.empty()
    );

    // Write the headers.
    if (header_res == QUICHE_H3_ERR_STREAM_BLOCKED) {
        stream.buffered_reply.written_headers = false;
    }
    else if (header_res < 0) {
        h3logger.warn("Unexpected error during quiche_h3_send_response: {}", header_res);
    }
    // Write the body if reply contains one and headers were written successfully.
    else if (!reply->_resp->_content.empty()) {
        body_res = quiche_h3_send_body(
                _h3_conn,
                this->_connection,
                reply->_stream_id,
                reinterpret_cast<uint8_t*>(reply->_resp->_content.data()),
                reply->_resp->content_length,
                true
        );
        if (body_res < -1) {
            h3logger.warn("[h3_connection::write]: writing reply body to stream ({}) has failed with error: {}.",
                          stream_id, body_res);
        }

        body_written = body_res < 0 ? 0 : static_cast<size_t>(body_res);
        stream.buffered_reply.body_iter = body_written;
    }

    stream.buffered_reply.reply = std::move(reply);

    return this->quic_flush().then([this, &stream] () {
       return wait_send_available(stream);
    });
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
future<> h3_connection<QI>::do_h3_poll() {
    if (!quiche_conn_is_established(this->_connection)) {
        return make_ready_future<>();
    }

    while(true) {
        quiche_h3_event* ev;
        auto s = quiche_h3_conn_poll(_h3_conn, this->_connection, &ev);

        if (s == QUICHE_ERR_DONE) {
            break;
        }
        else if (s < 0) {
            h3logger.warn("[h3_connection::do_h3_poll] Unexpected error during quiche_h3_conn_poll: {}", s);
        }

        auto& cur_req = _requests[s];

        // New request received.
        if (!cur_req._req) {
            cur_req = quic_h3_request(s);
        }

        switch (quiche_h3_event_type(ev)) {
            case QUICHE_H3_EVENT_HEADERS: {
                const auto rc = quiche_h3_event_for_each_header(ev, for_each_header, &cur_req);
                cur_req._req->_url     = cur_req._req->_headers[":path"];
                cur_req._req->_method  = cur_req._req->_headers[":method"];
                cur_req._req->_version = cur_req._req->_headers[":scheme"];
                cur_req._req->_headers["Host"] = cur_req._req->_headers[":authority"];

                if (rc != 0) {
                    fmt::print(stderr, "failed to process headers\n");
                }
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

                cur_req._req->content        = sstring(_buffer.data(), len);
                cur_req._req->content_length = len;
                break;
            }

            case QUICHE_H3_EVENT_FINISHED: {
                auto new_req = std::make_unique<quic_h3_request>(std::move(cur_req));
                _requests.erase(s);
                _read_queue.push(std::move(new_req));
                break;
            }

            case QUICHE_H3_EVENT_RESET:
                h3logger.warn("[h3_connection::do_h3_poll] Unhandled RESET event.");
                break;
            case QUICHE_H3_EVENT_PRIORITY_UPDATE:
                h3logger.warn("[h3_connection::do_h3_poll] Unhandled PRIORITY_UPDATE event.");
                break;
            case QUICHE_H3_EVENT_DATAGRAM:
                h3logger.warn("[h3_connection::do_h3_poll] Unhandled DATAGRAM event.");
                break;
            case QUICHE_H3_EVENT_GOAWAY:
                h3logger.warn("[h3_connection::do_h3_poll] Unhandled GOAWAY event.");
                break;
        }

        quiche_h3_event_free(ev);
    }

    return make_ready_future<>();
}

template <typename QI>
future<> h3_connection<QI>::h3_recv_loop() {
    return keep_doing([this] {
        return this->_read_marker.get_shared_future().then([this] {
            return do_h3_poll();
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
using h3_server_connection = typename h3_server::connection_type;

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
    future<> abort() {
        return _connection->abort();
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

future<std::unique_ptr<quic_h3_request>> quic_h3_connected_socket::read() {
    return future<std::unique_ptr<quic_h3_request>>(_impl->read());
}

future<> quic_h3_connected_socket::write(std::unique_ptr<quic_h3_reply> reply) {
    return future<>(_impl->write(std::move(reply)));
}

future<> quic_h3_connected_socket::abort() {
    return _impl->abort();
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

future<> connection::stop() {
    _replies.abort(std::make_exception_ptr(net::quic_aborted_exception()));
    return _socket.abort();
}

future<> http3_server::listen(socket_address addr, const std::string &cert_file, const std::string &cert_key,
                                  [[maybe_unused]] const net::quic_connection_config &quic_config)
{
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
        auto conn = std::make_unique<connection>(*this, std::move(result.connection));
        (void) try_with_gate(_task_gate, [conn = std::move(conn)] () mutable {
            return conn->process().handle_exception([conn = std::move(conn)] (const std::exception_ptr& e) {
                h3logger.debug("Connection processing error: {}", e);
            });
        }).handle_exception_type([] (const gate_closed_exception& e) {
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
        (void) conn.stop();
    }
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
