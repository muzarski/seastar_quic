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

// Things to be implemented.
#include <seastar/net/quic.hh>

// Basic definintions.
#include "common/quic_basic_connection.hh"
#include "common/quic_client_instance.hh"
#include "common/quic_engine.hh"
#include "common/quic_server_instance.hh"

// Seastar features.
#include <seastar/core/do_with.hh>          // seastar::do_with
#include <seastar/core/future.hh>           // seastar::future
#include <seastar/core/loop.hh>             // seastar::do_until, seastar::do_for_each
#include <seastar/core/shared_ptr.hh>       // seastar::enable_lw_shared_from_this
#include <seastar/core/temporary_buffer.hh> // seastar::temporary_buffer
#include <seastar/core/shared_future.hh>    // seastar::shared_promise

// Third-party API.
#include <quiche.h>

// Debug features.
#include <fmt/core.h>

// STD.
#include <deque>
#include <optional>
#include <unordered_map>


namespace seastar::net {
namespace {



//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//@|=================================|@
//@|.................................|@
//@|.................................|@
//@|.......... Declarations .........|@
//@|.................................|@
//@|.................................|@
//@|=================================|@
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@



// We can't get rid of this template parameter yet.
// It's because a QUIC server and a QUIC client
// will have different socket types.
template<typename QI>
class quic_connection final
        : public quic_basic_connection<QI>
        , public enable_lw_shared_from_this<quic_connection<QI>>
{
// Constants.
private:
    constexpr static size_t STREAM_READ_QUEUE_SIZE = 10'000;

// Local definitions.
private:
    using super_type = quic_basic_connection<QI>;
public:
    using type          = quic_connection<QI>;
    using instance_type = QI;

// Local structures.
private:
    using typename super_type::marker;

    struct quic_stream {
    public:
        // Data to be read from the stream.
        queue<temporary_buffer<quic_byte_type>>      read_queue = queue<temporary_buffer<quic_byte_type>>(STREAM_READ_QUEUE_SIZE);
        // Data to be sent via the stream.
        std::deque<temporary_buffer<quic_byte_type>> write_queue;
        // A field used for providing the user of the API
        // with the information when they will be able to
        // send data via the stream again (by producing
        // a `shared_future` from the `shared_promise`)
        // -- the future will only hold a value when
        // they can send data via the stream again.
        //
        // The value of the field is normally equal
        // to `std::nullopt` except when the stream
        // is cluttered and cannot accept more data,
        // in which case it holds a promise.
        std::optional<shared_promise<>>              maybe_writable = std::nullopt;
        // Flag signalizing whether output has been shutdown on the stream.
        // Used as a guard for future writes.
        marker                                       shutdown_output;
    };

// Fields.
protected:
    std::unordered_map<quic_stream_id, quic_stream> _streams;
    shared_promise<>                                _closed_promise;
    future<>                                        _stream_recv_fiber;
    std::optional<shared_future<>>                  _aborted = std::nullopt;

// Constructors and the destructor.
public:
    template<typename... Args>
    explicit quic_connection(Args&&... args)
    : super_type(std::forward<Args>(args)...)
    , _streams()
    , _closed_promise()
    , _stream_recv_fiber(make_ready_future())
    {
        this->_socket->register_connection(this->shared_from_this());
    }

    ~quic_connection() = default;

// Public methods.
public:
    void init();
    future<> abort();
    void close();

    void shutdown_all_output() {
        for (auto& [stream_id, _] : _streams) {
            shutdown_output(stream_id);
        }
    }

    // Send a message via a stream.
    future<> write(temporary_buffer<quic_byte_type> tb, quic_stream_id stream_id);
    // Read a message from a stream.
    future<temporary_buffer<quic_byte_type>> read(quic_stream_id stream_id);

    void send_outstanding_data_in_streams_if_possible();
    void shutdown_output(quic_stream_id stream_id);
    future<> closed();

// Private methods.
private:
    future<> stream_recv_loop();
    future<> wait_send_available(quic_stream_id stream_id);
};


template<typename ConnectionT>
class quiche_data_source_impl final : public data_source_impl {
// Local definitions.
public:
    using connection_type = ConnectionT;

// Fields.
private:
    lw_shared_ptr<connection_type> _connection;
    quic_stream_id                 _stream_id;

// Constructors + the destructor.
public:
    quiche_data_source_impl(lw_shared_ptr<connection_type> conn, quic_stream_id stream_id) noexcept
    : _connection(conn)
    , _stream_id(stream_id) {}

    ~quiche_data_source_impl() = default;

// Public methods.
public:
    future<temporary_buffer<quic_byte_type>> get() override {
        return _connection->read(_stream_id);
    }

    future<> close() override {
	    return make_ready_future<>();
    }
};


template<typename ConnectionT>
class quiche_data_sink_impl final : public data_sink_impl {
// Constants.
private:
    constexpr static size_t BUFFER_SIZE = MAX_DATAGRAM_SIZE;

// Local definitions.
public:
    using connection_type = ConnectionT;

// Fields.
private:
    lw_shared_ptr<connection_type> _connection;
    quic_stream_id                 _stream_id;

// Constructors + the destructor.
public:
    quiche_data_sink_impl(lw_shared_ptr<connection_type> conn, quic_stream_id stream_id) noexcept
    : _connection(conn)
    , _stream_id(stream_id) {}

    ~quiche_data_sink_impl() = default;

// Public methods.
public:
    future<> put(packet data) override {
        return do_with(std::move(data), [=](auto&& d) {
            auto fragments = d.fragments();
            return do_for_each(fragments.begin(), fragments.end(), [=](auto&& frag) {
                return _connection->write(temporary_buffer<char>(frag.base, frag.size), _stream_id);
            });
        });
    }

    future<> close() override {
        // TODO: implement this by sending FIN frame to the endpoint.
        // Although, here we should wait until all data in the stream is sent - how to do it efficiently?
        _connection->shutdown_output(_stream_id);
        return make_ready_future();
    }

    [[nodiscard]] size_t buffer_size() const noexcept override {
        return BUFFER_SIZE;
    }
};


template<typename ConnectionT>
class quiche_quic_connected_socket_impl : public quic_connected_socket_impl {
// Local definitions.
public:
    using connection_type = ConnectionT;
private:
    using data_source_type = quiche_data_source_impl<connection_type>;
    using data_sink_type   = quiche_data_sink_impl<connection_type>;

// Fields.
private:
    lw_shared_ptr<connection_type> _connection;

// Constructors + the destructor.
public:
    explicit quiche_quic_connected_socket_impl(lw_shared_ptr<connection_type> conn)
    : _connection(conn) {}

    ~quiche_quic_connected_socket_impl() noexcept override {
        _connection->close();
    }

// Public methods.
public:
    void shutdown_all_output() override {
        _connection->shutdown_all_output();
    }

    data_source source(quic_stream_id stream_id) override {
        return data_source(std::make_unique<data_source_type>(_connection, stream_id));
    }

    data_sink sink(quic_stream_id stream_id) override {
        return data_sink(std::make_unique<data_sink_type>(_connection, stream_id));
    }

    void shutdown_output(quic_stream_id stream_id) override {
        _connection->shutdown_output(stream_id);
    }

    future<> close() override {
        _connection->close();
        return _connection->closed();
    }
};



//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//@|=================================|@
//@|.................................|@
//@|.................................|@
//@|.......... Definitions ..........|@
//@|.................................|@
//@|.................................|@
//@|=================================|@
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@



//========================
//........................
//........................
//... quic connection ....
//........................
//........................
//========================


template<typename QI>
void quic_connection<QI>::init() {
    super_type::init();

    _stream_recv_fiber = try_with_gate(this->qgate(), [this] {
        return stream_recv_loop().handle_exception_type([] (const quic_aborted_exception& e) { qlogger.info("[quic_connection::stream_recv_loop] finished"); });
    }).handle_exception_type([] (const gate_closed_exception& e) {
    }).handle_exception([] (const std::exception_ptr& e) {
        qlogger.warn("[quic_connection]: stream receive loop error: {}", e);
    });
}

template<typename QI>
future<> quic_connection<QI>::abort() {
    if (_aborted) {
        return _aborted->get_future();
    }

    _closed_promise.set_value();
    this->_read_marker.abort();

    shared_promise<> aborted{};
    _aborted.emplace(aborted.get_shared_future());
    if (this->_connect_done_promise) {
        this->_connect_done_promise->set_exception(std::make_exception_ptr(quic_aborted_exception()));
    }

    if (this->_send_queue.size() > 0) {
        qlogger.warn("[quic_connection::abort] there is some unsent data in pacing queue for stream.");
    }

    // Abort streams' read and write queues.
    for (auto& [_, stream] : _streams) {
        stream.read_queue.abort(std::make_exception_ptr(quic_aborted_exception()));
        if (stream.maybe_writable) {
            stream.maybe_writable->set_exception(std::make_exception_ptr(quic_aborted_exception()));
        }
    }

    this->_timeout_timer.cancel();
    this->_send_timer.cancel();

    return _stream_recv_fiber.then([this, aborted = std::move(aborted)] () mutable {
        return this->_socket->handle_connection_aborting(this->_connection_id).then([aborted = std::move(aborted)] () mutable {
            aborted.set_value();
        });
    });
}

template<typename QI>
future<> quic_connection<QI>::closed() {
    return _closed_promise.get_shared_future();
}

template<typename QI>
void quic_connection<QI>::close() {
    if (this->_closing_marker || this->is_closed()) {
        return;
    }

    for (auto& [_, stream] : _streams) {
        if (!stream.write_queue.empty()) {
            qlogger.warn("[quic_connection::close] Called close on the connection whose data has not been sent yet.");
        }
    }

    this->_closing_marker.mark();
    // Although the documentation of Quiche does not specify the buffer being passed here
    // cannot be a NULL pointer, it is an assumption made by Rust's standard library.
    //
    // Violating this may lead to undefined behavior or panic.
    //
    // For more information, see the implementation of this function. As of the time of these changes,
    // it uses Rust's: `slice::from_raw_parts` where the assumption about the pointer being non-null is made.
    quiche_conn_close(this->_connection, true, 0, (const uint8_t*) "", 0);
    (void) this->quic_flush();
}

template<typename QI>
future<> quic_connection<QI>::write(temporary_buffer<quic_byte_type> tb, quic_stream_id stream_id) {
    if (this->is_closed()) {
        qlogger.warn("[quic_connection::write]: Called write after close.");
        return make_ready_future<>();
    }

    auto& stream = _streams[stream_id];
    if (stream.shutdown_output) {
        qlogger.debug("[quic_connection::write]: called write on stream ({}) whose output has been shutdown.", stream_id);
        return make_ready_future<>();
    }

    const auto written = quiche_conn_stream_send(
            this->_connection,
            stream_id,
            reinterpret_cast<const uint8_t*>(tb.get()),
            tb.size(),
            false
    );

    if (written < -1) {
        qlogger.warn("[quic_connection::write]: writing to stream ({}) has failed with error: {}.", stream_id, written);
    }

    const auto actually_written = written < 0 ? 0 : static_cast<size_t>(written);

    if (actually_written != tb.size()) {
        tb.trim_front(actually_written);
        // TODO: Can a situation like this happen that Quiche keeps track
        // of a stream but we don't store it in the map? Investigate it.
        // In such a case, we should catch an exception here and report it.
        stream.write_queue.push_front(std::move(tb));
    }

    return this->quic_flush().then([stream_id, this] {
        return wait_send_available(stream_id);
    });
}

template<typename QI>
future<temporary_buffer<quic_byte_type>> quic_connection<QI>::read(quic_stream_id stream_id) {
    if (this->is_closed()) {
        // EOF
        return make_ready_future<temporary_buffer<quic_byte_type>>(
                quic_make_eof_buffer<quic_byte_type>());
    }

    auto& stream = _streams[stream_id];

    return stream.read_queue.pop_eventually().then_wrapped([] (auto fut) {
        if (fut.failed()) {
            // quic_aborted_exception.
            fut.get_exception();
            return make_ready_future<temporary_buffer<quic_byte_type>>(
                    quic_make_eof_buffer<quic_byte_type>());
        }
        return fut;
    });
}

template<typename QI>
void quic_connection<QI>::send_outstanding_data_in_streams_if_possible() {
    auto* iter = quiche_conn_writable(this->_connection);
    quic_stream_id stream_id;

    while (quiche_stream_iter_next(iter, &stream_id)) {
        auto& stream = _streams[stream_id];
        auto& queue = stream.write_queue;

        while (!queue.empty()) {
            auto qb = std::move(queue.front());
            queue.pop_front();

            const auto written = quiche_conn_stream_send(
                    this->_connection,
                    stream_id,
                    reinterpret_cast<const uint8_t*>(qb.get()),
                    qb.size(),
                    false
            );

            if (written < 0) {
                qlogger.warn("[quic_connection::send_outstanding_data]: writing to stream ({}) has failed with error: {}.", stream_id, written);
            }

            const auto actually_written = written < 0 ? 0 : static_cast<size_t>(written);

            if (actually_written != qb.size()) {
                qb.trim_front(actually_written);
                queue.push_front(std::move(qb));
                break;
            }
        }

        if (quiche_conn_stream_capacity(this->_connection, stream_id) > 0) {
            if (stream.maybe_writable) {
                stream.maybe_writable->set_value();
                stream.maybe_writable = std::nullopt;
            }
        }
    }
    quiche_stream_iter_free(iter);
}

template<typename QI>
void quic_connection<QI>::shutdown_output(quic_stream_id stream_id) {
    auto& stream = _streams[stream_id];
    if (stream.shutdown_output) {
	    return;
    }

    stream.shutdown_output.mark();
    if (stream.maybe_writable) {
        stream.maybe_writable->set_exception(std::runtime_error("Output has been shutdown on the given stream."));
        stream.maybe_writable = std::nullopt;
    }

    // Although the documentation of Quiche does not specify the buffer being passed here
    // cannot be a NULL pointer, it is an assumption made by Rust's standard library.
    //
    // Violating this may lead to undefined behavior or panic.
    //
    // For more information, see the implementation of this function. As of the time of these changes,
    // it uses Rust's: `slice::from_raw_parts` where the assumption about the pointer being non-null is made.
    const auto err = quiche_conn_stream_send(this->_connection, stream_id, (const uint8_t*) "", 0, true);
    if (err < 0) {
        qlogger.warn("[quic_connection::shutdown_output]: quiche_conn_stream_send error "
                     "on stream ({}) when sending EOF: {}", stream_id, err);
    }

    if (stream.write_queue.size() > 0) {
        qlogger.info("[quic_connection::shutdown_output]: stream ({}) has non-emtpy write_queue. "
                     "Queue size: {}", stream_id, stream.write_queue.size());
    }

    (void) this->quic_flush();
}

template<typename QI>
future<> quic_connection<QI>::stream_recv_loop() {
    return keep_doing([this] {
        return this->_read_marker.get_shared_future().then([this] {
            quic_stream_id stream_id;
            auto iter = quiche_conn_readable(this->_connection);

            while (quiche_stream_iter_next(iter, &stream_id)) {
                auto& stream = _streams[stream_id];

                if (stream.read_queue.full()) {
                    continue;
                }

                // TODO for danmas: think about it
                if (quiche_conn_stream_finished(this->_connection, stream_id)) {
                    stream.read_queue.push(quic_make_eof_buffer<char>());
                    continue;
                }

                while (quiche_conn_stream_readable(this->_connection, stream_id)) {
                    bool fin = false;
                    const auto recv_result = quiche_conn_stream_recv(
                            this->_connection,
                            stream_id,
                            reinterpret_cast<uint8_t*>(this->_buffer.data()),
                            this->_buffer.size(),
                            &fin
                    );

                    if (recv_result < 0) {
                        // TODO: Handle this properly.
                        qlogger.warn("[quic_connection::stream_recv_loop] Reading from stream ({}) failed with error code {}",
                                     stream_id, recv_result);
                    } else {
                        temporary_buffer<quic_byte_type> message{this->_buffer.data(), static_cast<size_t>(recv_result)};
                        // TODO: Wrap this in some kind of `not_full` future
                        // (or just read only when necessary).
                        // TODO2: Learn more about exceptions that might be thrown here.
                        stream.read_queue.push(std::move(message));
                    }
                }
            }

            quiche_stream_iter_free(iter);

            if (!quiche_conn_is_readable(this->_connection)) {
                this->_read_marker.reset();
            }

            return this->quic_flush();
        });
    });
}

template<typename QI>
future<> quic_connection<QI>::wait_send_available(quic_stream_id stream_id) {
    if (quiche_conn_stream_capacity(this->_connection, stream_id) > 0) {
        return make_ready_future<>();
    } else {
        auto& stream = _streams[stream_id];
        if (!stream.maybe_writable.has_value()) {
            stream.maybe_writable = shared_promise<>{};
        }
        return stream.maybe_writable->get_shared_future();
    }
}


//============================
//............................
//............................
//. Getting rid of templates .
//............................
//............................
//============================



using quic_server = quic_server_instance<quic_connection>;
using quic_client = quic_client_instance<quic_connection>;

using quic_server_connection = typename quic_server::connection_type;
using quic_client_connection = typename quic_client::connection_type;

using quic_engine_type = quic_engine<quic_server, quic_client>;



//============================
//............................
//............................
//...... Core methods ........
//............................
//............................
//============================



lw_shared_ptr<quic_server> quiche_listen(const socket_address& sa,
        const std::string_view cert_file, const std::string_view cert_key,
        const quic_connection_config& quic_config, const size_t queue_length = 100)
{
    auto instance = make_lw_shared<quic_server>(
            sa, cert_file, cert_key, quic_config, queue_length);
    instance->init();
    quic_engine_type::register_instance(sa, instance);
    return instance;
}

lw_shared_ptr<quic_client_connection> quiche_connect(const socket_address& sa,
        const quic_connection_config& quic_config)
{
    auto instance = make_lw_shared<quic_client>(quic_config);
    auto conn_data = instance->connect(sa);
    if (!conn_data.conn) {
        throw std::runtime_error("Quiche_conn has failed.");
    }
    instance->init();

    quic_engine_type::register_instance(instance->local_address(), instance);
    return make_lw_shared<quic_client_connection>(
            conn_data.conn, instance->weak_from_this(), sa, conn_data.id);
}


class quiche_server_socket_impl final : public quic_server_socket_impl {
// Local definitions.
private:
    using implementation_type = quiche_quic_connected_socket_impl<quic_server_connection>;

// Fields.
private:
    lw_shared_ptr<quic_server> _listener;

// Constructors + the destructor.
public:
    quiche_server_socket_impl(const socket_address& sa, const std::string_view cert_file,
            const std::string_view cert_key, const quic_connection_config& quic_config)
    : _listener(quiche_listen(sa, cert_file, cert_key, quic_config)) {}

    ~quiche_server_socket_impl() = default;

// Implementation.
public:
    future<quic_accept_result> accept() override {
        return _listener->accept().then([] (lw_shared_ptr<quic_server_connection> conn) {
            auto impl = std::make_unique<implementation_type>(conn);

            return make_ready_future<quic_accept_result>(quic_accept_result {
                .connection     = quic_connected_socket(std::move(impl)),
                .remote_address = conn->remote_address()
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

void quiche_log_printer(const char* line, [[maybe_unused]] void*) {
    std::cout << line << std::endl;
}

class quiche_q_socket_impl : public q_socket_impl{
    quiche_configuration                  _config;
    lw_shared_ptr<quic_client_connection> _conn;
public:

    explicit quiche_q_socket_impl(const quic_connection_config& quic_config)
            : _config(quic_config), _conn() {}
    virtual future<net::quic_connected_socket> connect(socket_address sa) override {
        return quic_connect(sa);
    };
    virtual void set_reuseaddr(bool reuseaddr) override {};
    virtual bool get_reuseaddr() const override { return false; };
    virtual void shutdown() override {
        if (_conn) {
            //TODO take care of the return value
            fmt::print("Connection is closed after shutdown.\n");
            _conn->close();
        }
    }
};

socket_address shard_aware_address(socket_address sa) {
    return {ipv4_addr(sa.as_posix_sockaddr_in().sin_addr, sa.port() + this_shard_id())};
}
} // anonymous namespace



//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//@|=================================|@
//@|.................................|@
//@|.................................|@
//@|......... Implementation ........|@
//@|.................................|@
//@|.................................|@
//@|=================================|@
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@



quic_server_socket quic_listen(const socket_address& sa, const std::string_view cert_file,
        const std::string_view cert_key, const quic_connection_config& quic_config)
{
    socket_address _sa = shard_aware_address(sa);
    return quic_server_socket(std::make_unique<quiche_server_socket_impl>(_sa, cert_file, cert_key, quic_config));
}

future<quic_connected_socket> quic_connect(const socket_address& sa,
        const quic_connection_config& quic_config)
{
    using impl_type = quiche_quic_connected_socket_impl<quic_client_connection>;
    socket_address _sa = shard_aware_address(sa);

    try {
        auto connection = quiche_connect(_sa, quic_config);
        connection->init();
        return connection->connect_done().then([connection] {
            auto impl = std::make_unique<impl_type>(connection);
            return make_ready_future<quic_connected_socket>(std::move(impl));
        });
    } catch (const std::exception& e) {
        return make_exception_future<quic_connected_socket>(std::make_exception_ptr(e));
    }
}

input_stream<quic_byte_type> quic_connected_socket::input(quic_stream_id id) {
    return input_stream<quic_byte_type>(_impl->source(id));
}

output_stream<quic_byte_type> quic_connected_socket::output(quic_stream_id id, size_t buffer_size) {
    output_stream_options opts;
    opts.batch_flushes = true;
    return {_impl->sink(id), buffer_size};
}


void quic_connected_socket::shutdown_output(quic_stream_id id) {
    return _impl->shutdown_output(id);
}

void quic_connected_socket::shutdown_all_input() {
    //TODO
//    return _impl->shutdown_all_input();
}

void quic_enable_logging() {
    quiche_enable_debug_logging(quiche_log_printer, nullptr);
}

q_socket new_q_socket() {
    return q_socket(std::make_unique<quiche_q_socket_impl>(quic_connection_config()));
}

} // namespace seastar::net

