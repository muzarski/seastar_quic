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

// Seastar features.
#include <seastar/core/future.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/shared_future.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/core/weak_ptr.hh>
#include <seastar/core/queue.hh>
#include <seastar/net/api.hh>
#include <seastar/net/socket_defs.hh>

#include <seastar/http/http3.hh>

// Debug features.
#include <fmt/core.h>   // For development purposes, ditch this later on.

// Third-party API.
#include <quiche.h>

// STD.
#include <algorithm>
#include <chrono>           // Pacing
#include <cstring>          // std::memset, etc.
#include <memory>
#include <optional>
#include <random>           // Generating connection IDs
#include <string>           // TODO: Probably to be ditched.
#include <string_view>
#include <queue>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

// TODO: Think if some classes/structs should/should not be marked as `final`.

namespace seastar::net {

namespace {

// Provide type safety.
constexpr size_t MAX_CONNECTION_ID_LENGTH = QUICHE_MAX_CONN_ID_LEN;
// TODO: Remove if unnecessary.
constexpr size_t MAX_DATAGRAM_SIZE = 65'507;


//==============================
//..............................
//..............................
// Configuration of the socket.
//..............................
//..............................
//==============================

logger qlogger("quic");

class user_closed_connection_exception : public std::exception {
    [[nodiscard]] const char* what() const noexcept override {
        return "User closed the connection.";
    }
};


class quiche_configuration final {
private:
    // TODO: For the time being, store these statically to make development easier.
    constexpr static const char PROTOCOL_LIST[] = QUICHE_H3_APPLICATION_PROTOCOL; //"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9";
    // TODO !!!!!! current version is http3 specific - change this so both are properly used when needed
private:
    quiche_config* _config = nullptr;

public:
    quiche_configuration() = delete;
    quiche_configuration(const quiche_configuration&) = delete;
    quiche_configuration& operator=(const quiche_configuration&) = delete;

    quiche_configuration(quiche_configuration&& other) noexcept
    : _config(std::exchange(other._config, nullptr))
    {}

    quiche_configuration& operator=(quiche_configuration&& other) noexcept {
        if (this != std::addressof(other)) {
            _config = std::exchange(other._config, nullptr);
        }
        return *this;
    }

    explicit quiche_configuration(const quic_connection_config& config)
    : _config(quiche_config_new(QUICHE_PROTOCOL_VERSION))
    {
        if (!_config) {
            throw std::bad_alloc{};
        }

        // TODO check return value
        quiche_config_set_application_protos(
            _config,
            reinterpret_cast<const uint8_t*>(PROTOCOL_LIST),
            sizeof(PROTOCOL_LIST) - 1
        );

        if (_config == nullptr) {
            // std::cout << "failed to create config" << std::endl;

        }
        constexpr auto convert_cc = [](quic_cc_algorithm cc) constexpr noexcept -> quiche_cc_algorithm {
            switch (cc) {
                case quic_cc_algorithm::BBR:    return QUICHE_CC_BBR;
                case quic_cc_algorithm::CUBIC:  return QUICHE_CC_CUBIC;
                case quic_cc_algorithm::RENO:   return QUICHE_CC_RENO;
            }
            return QUICHE_CC_RENO;
        };

        if (config.max_idle_timeout) {
            quiche_config_set_max_idle_timeout(_config, config.max_idle_timeout.value());
        }
        quiche_config_set_max_recv_udp_payload_size(_config, config.max_recv_udp_payload_size);
        quiche_config_set_max_send_udp_payload_size(_config, config.max_send_udp_payload_size);
        quiche_config_set_initial_max_data(_config, config.initial_max_data);
        quiche_config_set_initial_max_stream_data_bidi_local(_config, config.initial_max_stream_data_bidi_local);
        quiche_config_set_initial_max_stream_data_bidi_remote(_config, config.initial_max_stream_data_bidi_remote);
        quiche_config_set_initial_max_stream_data_uni(_config, config.initial_max_stream_data_uni);
        quiche_config_set_initial_max_streams_bidi(_config, config.initial_max_streams_bidi);
        quiche_config_set_initial_max_streams_uni(_config, config.initial_max_streams_uni);
        quiche_config_set_disable_active_migration(_config, config.disable_active_migration);
        quiche_config_set_cc_algorithm(_config, convert_cc(config.congestion_control_algorithm));
        quiche_config_set_max_stream_window(_config, config.max_stream_window);
        quiche_config_set_max_connection_window(_config, config.max_connection_window);
    }

    quiche_configuration(const std::string_view cert_filepath, const std::string_view key_filepath,
            const quic_connection_config& config)
    : quiche_configuration(config)
    {
        constexpr auto handle_quiche_err = [&](auto return_code, const auto& msg) {
            constexpr decltype(return_code) OK_CODE = 0;
            if (return_code != OK_CODE) {
                // TODO: For the time being, to make development a bit easier.
                fmt::print(stderr, "Error while initializing the QUIC configuration: \"{}\"", msg);
                throw std::runtime_error("Could not initialize a quiche configuration.");
            }
        };

        handle_quiche_err(
            quiche_config_load_cert_chain_from_pem_file(_config, cert_filepath.data()),
            "Loading the certificate file has failed."
        );
        handle_quiche_err(
            quiche_config_load_priv_key_from_pem_file(_config, key_filepath.data()),
            "Loading the key file has failed."
        );
    }

    ~quiche_configuration() noexcept {
        if (_config) {
            quiche_config_free(std::exchange(_config, nullptr));
        }
    }

    quiche_config* get_underlying_config() noexcept {
        return _config;
    }
};


//========================
//........................
//........................
// Connection identifier.
//........................
//........................
//========================


struct connection_id {
    uint8_t _cid[MAX_CONNECTION_ID_LENGTH]{};

    connection_id() {
        std::memset(_cid, 0, sizeof(_cid));
    }

    static connection_id generate() {
        static std::mt19937 mersenne(std::chrono::system_clock::now().time_since_epoch().count());

        connection_id result;

        constexpr static size_t CID_LENGTH = sizeof(_cid);
        size_t offset = 0;

        while (offset < CID_LENGTH) {
            const auto random_number = mersenne();
            std::memcpy(result._cid + offset, &random_number, std::min(sizeof(random_number), CID_LENGTH - offset));
            offset += sizeof(random_number);
        }

        return result;
    }

    bool operator==(const connection_id& other) const noexcept {
        return std::memcmp(_cid, other._cid, sizeof(_cid)) == 0;
    }
};

} // anonymous namespace
} // namespace seastar::net

namespace std {

// So that `std::unordered_map` can use `connection_id` as the key type.
template<>
struct hash<seastar::net::connection_id> {
    size_t operator()(seastar::net::connection_id cid) const noexcept {
        size_t result = 0;
        for (auto it = std::begin(cid._cid); it != std::end(cid._cid); ++it) {
            result ^= *it + 0x9e3779b9
                    + (seastar::net::MAX_CONNECTION_ID_LENGTH << 6)
                    + (seastar::net::MAX_CONNECTION_ID_LENGTH >> 2);
        }
        return result;
    }
};

} // namespace std

namespace seastar::net {
namespace {


//=====================
//.....................
//.....................
// Network UDP manager
//.....................
//.....................
//=====================


using quic_buffer = temporary_buffer<quic_byte_type>;

struct send_payload {
    quic_buffer     buffer;
    socket_address  dst;

    send_payload() = default;

    send_payload(quic_buffer&& buf, const socket_address& dest)
    : buffer(std::move(buf))
    , dst(dest)
    {}

    send_payload(quic_buffer&& buf, const ::sockaddr_storage& dest, ::socklen_t dest_len)
    : buffer(std::move(buf))
    {
        // TODO: Handle IPv6.
        ::sockaddr_in addr_in{};
        std::memcpy(std::addressof(addr_in), std::addressof(dest), dest_len);
        dst = addr_in;
    }
};

class marker {
private:
    bool _marked = false;

public:
    constexpr void mark() noexcept { _marked = true; }
    constexpr operator bool() const noexcept { return _marked; }
};

class quic_udp_channel_manager {
private:
    constexpr static size_t WRITE_QUEUE_SIZE = 212'992;
    constexpr static size_t READ_QUEUE_SIZE  = 212'992;

private:
    udp_channel         _channel;
    future<>            _write_fiber;
    future<>            _read_fiber;
    queue<send_payload> _write_queue;
    queue<udp_datagram> _read_queue;
    marker              _closed;

public:
    quic_udp_channel_manager()
    : _channel(make_udp_channel())
    , _write_fiber(make_ready_future<>())
    , _read_fiber(make_ready_future<>())
    , _write_queue(WRITE_QUEUE_SIZE) // TODO: decide on what packet qs size to use
    , _read_queue(READ_QUEUE_SIZE)
    , _closed() {}

    explicit quic_udp_channel_manager(const socket_address& sa)
    : _channel(make_udp_channel(sa))
    , _write_fiber(make_ready_future<>())
    , _read_fiber(make_ready_future<>())
    , _write_queue(WRITE_QUEUE_SIZE) // TODO: decide on what packet qs size to use
    , _read_queue(READ_QUEUE_SIZE)
    , _closed() {}

    [[nodiscard]] socket_address local_address() const {
        return _channel.local_address();
    }

    future<> send(send_payload&& payload) {
        return _write_queue.push_eventually(std::move(payload));
    }

    future<udp_datagram> read() {
        // std::cout << "In HTTP3 channel read(): " << _read_queue.size() << std::endl;

        return _read_queue.pop_eventually();
    }

    void init() {
        _read_fiber = read_loop();
        _write_fiber = write_loop();
    }

    future<> close() {
        if (_closed) {
            return make_ready_future<>();
        }

        _closed.mark();
        _channel.shutdown_input();
        return _read_fiber.handle_exception([this] (const std::exception_ptr& e) {
            return _write_fiber.handle_exception([this] (const std::exception_ptr& e) {
                _channel.close();
                return make_ready_future<>();
            });
        });
    }

    void abort_queues(std::exception_ptr &&ex) {
        _write_queue.abort(ex);
        _read_queue.abort(ex);
    }

private:
    future<> read_loop() {
        // std::cout << "in channel read_loop" << std::endl;

        return do_until([this] { return bool(_closed); }, [this] {
            return _channel.receive().then([this] (udp_datagram datagram) {
                // std::cout << "in channel read_loop - got datagram" << std::endl;

                return _read_queue.push_eventually(std::move(datagram));
            });
        });
    }

    future<> write_loop() {
//        return do_until([this] { return _closed; }, [this] {
//            return seastar::make_ready_future<>();
////            return _write_queue.pop_eventually().then([this] (send_payload payload) {
////                return _channel.send(payload.dst, std::move(payload.buffer));
////            });
//        });

        return do_until(
                [this] { return bool(_closed); },
                [this] {
                    return _write_queue.pop_eventually().then([this] (send_payload payload) {
                        return _channel.send(payload.dst, std::move(payload.buffer));
                    });
                }
        );
    }
};

void quiche_log_printer(const char* line, void* args) {
    // std::cout << line << std::endl;
}

/*
//==================================================================
//..................................................................
//  Diagram of the design of QUIC and HTTP/3 support in this file.
//..................................................................
//==================================================================
//
//                          =============
//                           quic_engine
//                          =============
//                               T
//                               |
//                         ===============
//                          quic_instance
//                         ===============
//                          T           T
//                         /             \
//                        /               \
//                    ========             \
//                     server               \
//                    ========               \
//                      T  T                  \
//                     /    \                  \
//                    /      \                  \
//                   /        \                  \
//                  /          \                  \
//                 /            \                  \
//                /              \                  \
//           ===========    =============     =============
//            h3_server      quic_server       quic_client
//           ===========    =============     =============
//              T              T                          T
//              |              |                          |
//              |  ==========  |    ==================    |
//              |---listener---|     basic_connection     |
//              |  ==========  |    ==================    |
//              |              |            T             |
//              |              |            |             |
//           ===============   |     =================    |
//            h3_connection    \------quic_connection-----/
//           ===============         =================
//
//
//..................................................................
//==================================================================


//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//@|=================================|@
//@|.................................|@
//@|.................................|@
//@|......... Declarations ..........|@
//@|.................................|@
//@|.................................|@
//@|=================================|@
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
*/
struct connection_data {
    quiche_conn*   conn;
    connection_id  id;
    socket_address pa;
};


// Central "unit" keeping track of all instances of QUIC sockets.
template<typename... QIs>
class quic_engine {
// Local definitions.
private:
    // Wrap pointers in a variant, not the types.
    // Pointers have the same size.
    using instance_type = std::variant<lw_shared_ptr<QIs>...>;
    using my_type = quic_engine<QIs...>;

// Fields.
private:
    std::unordered_map<socket_address, instance_type> _instances;

    // Do not make this inline. `quic_engine<QIs...>` is an incomplete
    // type in this place, but we can declare it when no definition
    // is provided.
    //
    // "The declaration of a non-inline static data member in its class
    //  definition is not a definition and may be of an incomplete type
    //  other than cv void."
    //
    // --- Standard 12.2.3.2 [Static data members], revise N4659.
    //
    // See also: https://en.cppreference.com/w/cpp/language/static
    static thread_local quic_engine<QIs...>           _engine;

// Constructors + the destructor.
private:
    quic_engine() = default;

    quic_engine(const quic_engine&) = delete;
    quic_engine& operator=(const quic_engine&) = delete;

    ~quic_engine() = default;

// Public methods.
public:
    template<typename T>
    static void register_instance(const socket_address& key, lw_shared_ptr<T> instance) {
        static_assert(std::disjunction_v<std::is_same<T, QIs>...>,
                "Invalid instance type");

        init_engine();
        _engine._instances.emplace(key, instance);
    }

// Private methods.
private:
    static void init_engine() {
        thread_local marker cleanup_initialized;

        if (!cleanup_initialized) {
            engine().at_exit([] {
                future<> close_tasks = make_ready_future<>();
                for (auto& [_, instance] : my_type::_engine._instances) {
                    close_tasks = close_tasks.then([&instance = instance] {
                        return std::visit([] (auto ptr) {
                            return ptr->close();
                        }, instance);
                    });
                }
                return close_tasks;
            });
            cleanup_initialized.mark();
        }
    }
};

template<typename... QIs>
thread_local quic_engine<QIs...> quic_engine<QIs...>::_engine{};


// Servers are specified by the type of connections they hold,
// e.g. whether it's a HTTP/3 server or a "raw" QUIC server.
//
// The connection type is a template parameterized by
// the QUIC socket instance that holds it, i.e.
// this or some other instance class.
//
// Refer to the diagram above to get a more illustrative
// and high-level view on the design.
template<template<typename> typename ConnectionT>
class quic_server_instance : public weakly_referencable<quic_server_instance<ConnectionT>> {
// Local definitions.
public:
    using connection_type = ConnectionT<quic_server_instance<ConnectionT>>;
    using type            = quic_server_instance<ConnectionT>;

// Local constants.
private:
    // TODO: Check the comments left in the function `quic_retry`.
    // Right now, tokens aren't used properly and passing `socket_address::length()`
    // to quiche's functions causes validation of them return false. Investigate it.
    constexpr static size_t MAX_TOKEN_SIZE =
            sizeof("quiche") - 1 + sizeof(::sockaddr_storage) + MAX_CONNECTION_ID_LENGTH;

// Local structures.
private:
    template<size_t Length>
    struct cid_template {
        constexpr static size_t CID_MAX_LENGTH = Length;

        uint8_t data[Length];
        size_t  length = sizeof(data);
    };

    template<size_t TokenSize>
    struct header_token_template {
        constexpr static size_t HEADER_TOKEN_MAX_SIZE = TokenSize;

        uint8_t data[TokenSize];
        size_t  size = sizeof(data);
    };

    using cid          = cid_template<MAX_CONNECTION_ID_LENGTH>;
    using header_token = header_token_template<MAX_TOKEN_SIZE>;

    struct quic_header_info {
        uint8_t  type;
        uint32_t version;

        cid scid;
        cid dcid;
        cid odcid;

        header_token token;
    };

// Fields.
protected:
    quiche_configuration                                              _quiche_configuration;
    // TODO: Check if keeping this as a pointer is necessary.
    lw_shared_ptr<quic_udp_channel_manager>                           _channel_manager;
    std::vector<char>                                                 _buffer;
    std::unordered_map<connection_id, lw_shared_ptr<connection_type>> _connections;
    queue<lw_shared_ptr<connection_type>>                             _waiting_queue;
    future<>                                                          _send_queue;
    future<>                                                          _service_loop;
    marker                                                            _is_closing;

// Constructors and the destructor.
public:
    explicit quic_server_instance(const socket_address& sa, const std::string_view cert,
            const std::string_view key, const quic_connection_config& quic_config,
            const size_t queue_length)
    : _quiche_configuration(cert, key, quic_config)
    , _channel_manager(make_lw_shared<quic_udp_channel_manager>(sa))
    , _buffer(MAX_DATAGRAM_SIZE)
    , _waiting_queue(queue_length)
    , _send_queue(make_ready_future<>())
    , _service_loop(make_ready_future<>()) {}

    explicit quic_server_instance(const std::string_view cert, const std::string_view key,
            const quic_connection_config& quic_config, const size_t queue_length)
    : _quiche_configuration(cert, key, quic_config)
    , _channel_manager(make_lw_shared<quic_udp_channel_manager>())
    , _buffer(MAX_DATAGRAM_SIZE)
    , _waiting_queue(queue_length)
    , _send_queue(make_ready_future<>())
    , _service_loop(make_ready_future<>()) {}

    ~quic_server_instance() = default;

// Public methods.
public:
    future<> send(send_payload&& payload);
    future<> handle_connection_closing(const connection_id& cid);

    future<lw_shared_ptr<connection_type>> accept();
    void abort_accept() noexcept;

    [[nodiscard]] connection_data connect(const socket_address& sa);
    [[nodiscard]] socket_address local_address() const {
        return _channel_manager->local_address();
    }
    void register_connection(lw_shared_ptr<connection_type> conn);
    void init();
    // TODO: Ditch this.
    [[nodiscard]] std::string name() const;
    future<> close();

// Private methods.
private:
    future<> service_loop();
    future<> handle_datagram(udp_datagram&& datagram);
    future<> handle_post_hs_connection(lw_shared_ptr<connection_type> conn, udp_datagram&& datagram);
    // TODO: Check if we cannot provide const references here instead.
    future<> handle_pre_hs_connection(quic_header_info& header_info, udp_datagram&& datagram, connection_id& key);
    future<> negotiate_version(const quic_header_info& header_info, udp_datagram&& datagram);
    future<> quic_retry(const quic_header_info& header_info, udp_datagram&& datagram);
    connection_id generate_new_cid();


    static header_token mint_token(const quic_header_info& header_info, const ::sockaddr_storage* addr, ::socklen_t addr_len);
    // TODO: Change this function to something proper, less C-like.
    static bool validate_token(const uint8_t* token, size_t token_len, const ::sockaddr_storage* addr,
            ::socklen_t addr_len, uint8_t* odcid, size_t* odcid_len);
};

// Despite the fact that clients, unlike servers, cannot correspond
// to any type connection other than the "raw" QUIC one, we make this
// class a template for preserving a consistent code style.
//
// For the template parameter, see the comment for `quic_server_instance`.
template<template<typename> typename ConnectionT>
class quic_client_instance : public weakly_referencable<quic_client_instance<ConnectionT>> {
// Local definitions.
public:
    using connection_type = ConnectionT<quic_client_instance<ConnectionT>>;
    using type            = quic_client_instance<ConnectionT>;

// Fields.
protected:
    lw_shared_ptr<quic_udp_channel_manager> _channel_manager;
    quiche_configuration                    _quiche_configuration;
    lw_shared_ptr<connection_type>          _connection;
    future<>                                _receive_fiber;
    marker                                  _closing_marker;

// Constructors and the destructor.
public:
    explicit quic_client_instance(const quic_connection_config& quic_config)
    : _channel_manager(make_lw_shared<quic_udp_channel_manager>())
    , _quiche_configuration(quic_config)
    , _connection()
    , _receive_fiber(make_ready_future<>())
    , _closing_marker() {}

    ~quic_client_instance() = default;

// Public methods.
public:
    future<> send(send_payload&& payload);
    future<> handle_connection_closing(const connection_id& cid);
    [[nodiscard]] connection_data connect(const socket_address& sa);
    void register_connection(lw_shared_ptr<connection_type> conn);
    void init();
    // TODO: Ditch this.
    [[nodiscard]] std::string name();
    future<> close();
    [[nodiscard]] socket_address local_address() const {
        return _channel_manager->local_address();
    }

// Private methods.
private:
    future<> receive_loop();
    future<> receive();
};


// A basis for `connection`. Provides the following functionalities:
//   1) pacing,
//   2) sending packets after Quiche's preprocessing of data in streams,
//   3) passing data from the network to Quiche to process it
//      for specific streams.
//
// `QI` is the QUIC instance this connection type is stored by.
template<typename QI>
class basic_connection {
// Local definitions.
private:
    // Type of the timer responsible for timeout events.
    using timeout_timer = timer<std::chrono::steady_clock>;
    // Type of the timer responsible for sending data (pacing).
    using send_timer    = timer<std::chrono::steady_clock>;

    using timeout_clock = typename timeout_timer::clock;
    using send_clock    = typename send_timer::clock;

    using timeout_time_point    = typename timeout_timer::time_point;
    using timeout_time_duration = typename timeout_timer::duration;
    using send_time_point       = typename send_timer::time_point;
    using send_time_duration    = typename send_timer::duration;
protected:
    using type            = basic_connection<QI>;
    using instance_type   = QI;
    using connection_type = typename instance_type::connection_type;

// Local constants.
private:
    // Acceptable error when sending out packets. We use this to avoid
    // situations when the send timer needs to constantly call the callback
    // with very short breaks in between. Instead, we send everything
    // that ought to be sent within the span `[now, now + SEND_TIME_EPSILON]`.
    constexpr static send_time_duration SEND_TIME_EPSILON = std::chrono::nanoseconds(20);

// Local structures.
private:
    // Payload with a timestamp indicating when it should be sent.
    // Used for pacing.
    struct paced_payload {
    private:
        // When to send the data.
        send_time_point _time;
    public:
        // Data to be sent.
        send_payload payload;

    public:
        paced_payload(send_payload spl, const send_time_point& t)
        : _time(t), payload(std::move(spl)) {}

        // For providing the type with a total order so that
        // we can sort it.
        bool operator>(const paced_payload& other) const noexcept(noexcept(_time > other._time)) {
            return _time > other._time;
        }

        [[nodiscard]] const auto& get_time() const noexcept {
            return _time;
        }
    };

    // Class providing a way to mark data if there is some data
    // to be processed by the streams.
    class read_marker {
    private:
        // A `promise<>` used for generating `future<>`s to provide
        // a means to mark if there may be some data to be processed by
        // the streams, and to check the marker.
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

    // An extenstion of `std::priority_queue` to provide a means
    // to move the top element out of it.
    template<typename Elem, typename Container = std::vector<Elem>, typename Compare = std::greater<Elem>>
    class send_queue_template : public std::priority_queue<Elem, Container, Compare> {
    private:
        using super_type = std::priority_queue<Elem, Container, Compare>;

    public:
        Elem fetch_top() {
            std::pop_heap(super_type::c.begin(), super_type::c.end(), super_type::comp);
            Elem result = std::move(super_type::c.back());
            super_type::c.pop_back();
            return result;
        }
    };

    // The type of the container storing packets waiting to be sent
    // to the network.
    //
    // TODO: Investigate if Quiche specifies the timestamps
    // the library gives are always order in the non-decreasing order.
    // If that's the case, replace this with something more efficient,
    // for example with `std::queue`.
    using send_queue = send_queue_template<paced_payload>;

// Fields.
protected:
    // The Quiche connection instance corresponding to a particular `quic_connection`.
    // If `_connection` is equal to `nullptr`, the connection has already been invalidated
    // and no further clean-up is needed.
    quiche_conn*                 _connection;
    weak_ptr<instance_type>      _socket;
    // TODO: Check if keeping two buffers is necessary.
    std::vector<char>            _buffer;
    std::vector<char>            _out_buffer;

    const socket_address         _peer_address;

    send_timer                   _send_timer;
    timeout_timer                _timeout_timer;

    send_queue                   _send_queue;

    read_marker                  _read_marker;
    marker                       _closing_marker;

    promise<>                    _ensure_closed_promise;
    std::optional<promise<>>     _connect_done_promise;

    connection_id                _connection_id;

// Constructors + the destructor.
public:
    explicit basic_connection(quiche_conn* conn, weak_ptr<instance_type> socket,
            const socket_address& pa, const connection_id& id)
    : _connection(conn)
    , _socket(std::move(socket))
    , _buffer(MAX_DATAGRAM_SIZE)
    , _out_buffer(MAX_DATAGRAM_SIZE)
    , _peer_address(pa)
    , _send_timer()
    , _timeout_timer()
    , _ensure_closed_promise()
    , _connect_done_promise(std::in_place)
    , _connection_id(id) {}

    basic_connection(const basic_connection&) = delete;
    basic_connection& operator=(const basic_connection&) = delete;

    explicit basic_connection(basic_connection&& other) noexcept
    : _connection(std::exchange(other._connection, nullptr))
    , _socket(std::move(other._socket))
    , _buffer(std::move(other._buffer))
    , _out_buffer(std::move(other._out_buffer))
    , _peer_address(std::move(other._peer_address))
    , _send_timer(std::move(other._send_timer))
    , _timeout_timer(std::move(other._timeout_timer))
    , _send_queue(std::move(other._send_queue))
    , _read_marker(std::move(other._read_marker))
    , _closing_marker(std::move(other._closing_marker))
    , _ensure_closed_promise(std::move(other._ensure_closed_promise))
    , _connect_done_promise(std::move(other._connect_done_promise))
    , _connection_id(std::move(other._connection_id)) {}

    basic_connection& operator=(basic_connection&& other) noexcept {
        if (this != std::addressof(other)) {
            std::destroy_at(this);
            new (this) basic_connection<QI> (std::move(other));
        }
        return *this;
    }

    virtual ~basic_connection() noexcept {
        if (_connection) {
            quiche_conn_free(std::exchange(_connection, nullptr));
        }
    }

// Public methods.
public:
    // Initializes the callbacks and loops.
    void init();

    // Pass a datagram to process by the connection.
    void receive(udp_datagram&& datagram);

    // Virtualization doesn't hurt us here -- the method
    // is only going to be called once.
    //
    // It CANNOT be a pure virtual function, however.
    // Otherwise, we won't be able to instantiate the class,
    // while leaving it without a definition would cause
    // a linking error.
    virtual void close() {}
    bool is_closed() const noexcept;

    future<> quic_flush();

    future<> ensure_closed() noexcept;
    [[nodiscard]] socket_address remote_address();
    future<> connect_done();
    connection_id cid();

// Protected methods.
protected:
    bool is_closing() const noexcept;
};


// We can't get rid of this template parameter yet.
// It's because a QUIC server and a QUIC client
// will have different socket types.
template<typename QI>
class quic_connection final
        : public basic_connection<QI>
        , public enable_lw_shared_from_this<quic_connection<QI>>
        , public weakly_referencable<quic_connection<QI>>
{
// Constants.
private:
    constexpr static size_t STREAM_READ_QUEUE_SIZE = 10'000;

// Local definitions.
private:
    using super_type = basic_connection<QI>;
public:
    using type          = quic_connection<QI>;
    using instance_type = QI;

// Local structures.
private:
    struct quic_stream {
    public:
        // Data to be read from the stream.
        queue<quic_buffer>              read_queue = queue<quic_buffer>(STREAM_READ_QUEUE_SIZE);
        // Data to be sent via the stream.
        std::deque<quic_buffer>         write_queue;
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
        std::optional<shared_promise<>> maybe_writable = std::nullopt;
        // Flag signalizing whether output has been shutdown on the stream.
        // Used as a guard for future writes.
        bool                            shutdown_output = false;
    };

    // Class providing a way to mark data if there is some data
    // to be processed by the streams.
    class read_marker {
    private:
        // A `promise<>` used for generating `future<>`s to provide
        // a means to mark if there may be some data to be processed by
        // the streams, and to check the marker.
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
    std::unordered_map<quic_stream_id, quic_stream> _streams;
    future<>                                        _stream_recv_fiber;

// Constructors and the destructor.
public:
    template<typename... Args>
    explicit quic_connection(Args&&... args)
    : super_type(std::forward<Args>(args)...)
    , _streams()
    , _stream_recv_fiber(make_ready_future<>())
    {
        this->_socket->register_connection(this->shared_from_this());
        init();
    }

    ~quic_connection()  = default;

// Public methods.
public:
    void init();
    void close() override;

    // Send a message via a stream.
    future<> write(quic_buffer qb, quic_stream_id stream_id);
    // Read a message from a stream.
    future<quic_buffer> read(quic_stream_id stream_id);

    void send_outstanding_data_in_streams_if_possible();
    void shutdown_output(quic_stream_id stream_id);

// Private methods.
private:
    future<> stream_recv_loop();
    future<> wait_send_available(quic_stream_id stream_id);
};


template<typename QI>
class h3_connection final
        : public basic_connection<QI>
        , public enable_lw_shared_from_this<h3_connection<QI>>
        , public weakly_referencable<h3_connection<QI>>
{
// Constants.
private:
    constexpr static size_t H3_READ_QUEUE_SIZE = 10'000;
// Local definitions.
public:
    using type          = h3_connection<QI>;
    using instance_type = QI;

private:
    using super_type = basic_connection<QI>;

    quiche_h3_config* h3_config;
    quiche_h3_conn *_h3_conn = nullptr;

    static int for_each_header(uint8_t *name, size_t name_len,
                               uint8_t *value, size_t value_len,
                               void *argp) {

        auto *request_in_callback = static_cast<seastar::net::quic_h3_request*>(argp);

        char _name[name_len + 1];
        strncpy(_name, reinterpret_cast<const char *>(name), name_len);
        _name[name_len] = '\0';

        char _value[value_len + 1];
        strncpy(_value, reinterpret_cast<const char *>(value), value_len);
        _value[value_len] = '\0';
        request_in_callback->_req._headers[to_sstring(_name)] = to_sstring(_value); // TODO check if to_sstring actually works
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
    future<>                                        _stream_recv_fiber;
public:
    // Data to be read from the stream.
    queue< std::unique_ptr<quic_h3_request>>              read_queue = queue< std::unique_ptr<quic_h3_request>>(H3_READ_QUEUE_SIZE);
    // Data to be sent via the stream.
    std::deque<quic_buffer>         write_queue;

//    std::optional<shared_promise<>> maybe_writable = std::nullopt;

// Constructors + the destructor.
public:
    template<typename... Args>
    h3_connection(Args&&... args)
            : super_type(std::forward<Args>(args)...)
            , _stream_recv_fiber(make_ready_future<>())
    {
        // std::cout << "h3_connection constructor" << std::endl;

        this->_socket->register_connection(this->shared_from_this());
        init();
    }

    ~h3_connection() = default;

// Public methods.
public:
    void init();
    void close() override;
    future<std::unique_ptr<quic_h3_request>> read();
    future<> write(std::unique_ptr<quic_h3_reply> reply);
    void send_outstanding_data_in_streams_if_possible();
    promise<> _h3_connect_done_promise{};
// Private methods.
private:
    future<> h3_recv_loop();

//    future<> wait_send_available();
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
    future<quic_buffer> get() override {
        return _connection->read(_stream_id);
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
        const auto* fa = data.fragment_array();
        quic_buffer qb{reinterpret_cast<quic_byte_type*>(fa->base), static_cast<size_t>(fa->size)};

        return _connection->write(std::move(qb), _stream_id);
    }

    future<> close() override {
        // TODO: implement this by sending FIN frame to the endpoint.
        // Although, here we should wait until all data in the stream is sent - how to do it efficiently?
        return make_ready_future();
    }

    [[nodiscard]] size_t buffer_size() const noexcept override {
        // TODO: what buffer size should be chosen? Maybe MAX_STREAM_DATA from quiche config?
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
    data_source source(quic_stream_id stream_id) override {
        return data_source(std::make_unique<data_source_type>(_connection, stream_id));
    }

    data_sink sink(quic_stream_id stream_id) override {
        return data_sink(std::make_unique<data_sink_type>(_connection, stream_id));
    }

    void shutdown_output(quic_stream_id stream_id) override {
        _connection->shutdown_output(stream_id);
    }
};


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
        // std::cout << "h3 socket impl DELETING" << std::endl;
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
//. quic server instance .
//........................
//........................
//========================

template<template<typename> typename CT>
future<> quic_server_instance<CT>::send(send_payload&& payload) {
    return _channel_manager->send(std::move(payload));
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::handle_connection_closing(const connection_id& cid) {
    _connections.erase(cid);
    fmt::print("Server connection closed. Removed from the map.\n");
    return make_ready_future<>();
}

template<template<typename> typename CT>
future<lw_shared_ptr<typename quic_server_instance<CT>::connection_type>>
quic_server_instance<CT>::accept() {
    // std::cout << "In HTTP3 server accept: " << _waiting_queue.size() << std::endl;
    return _waiting_queue.not_empty().then([this] {
        return make_ready_future<lw_shared_ptr<connection_type>>(_waiting_queue.pop());
    });
}

template<template<typename> typename CT>
void quic_server_instance<CT>::abort_accept() noexcept {
    _waiting_queue.abort(std::make_exception_ptr(
            std::system_error(ECONNABORTED, std::system_category())));
}

// TODO: To ditch? Servers do NOT connect.
template<template<typename> typename CT>
[[nodiscard]] connection_data quic_server_instance<CT>::connect(const socket_address& sa) {
    throw std::runtime_error("Internal API error - bad state.");
}

template<template<typename> typename CT>
void quic_server_instance<CT>::register_connection(lw_shared_ptr<connection_type> conn) {
    _connections[conn->cid()] = conn;
}

template<template<typename> typename CT>
void quic_server_instance<CT>::init() {
    _channel_manager->init();
    _service_loop = service_loop();
}

// TODO: Ditch this.
template<template<typename> typename CT>
[[nodiscard]] std::string quic_server_instance<CT>::name() const {
    return "server";
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::close() {
    future<> close_tasks = make_ready_future<>();
    for (auto& conn : _connections) {
        close_tasks = close_tasks.then([conn = std::move(conn.second)] {
            // std::cout << "h3 server instance DELETING" << std::endl;

            conn->close();
            return conn->ensure_closed();
        });
    }

    return close_tasks.then([this] {
        _channel_manager->abort_queues(std::make_exception_ptr(user_closed_connection_exception()));
        return _service_loop.handle_exception([this] (const std::exception_ptr& e) {
            return _channel_manager->close();
        });
    });
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::service_loop() {
    // std::cout << "In HTTP3 service_loop" << std::endl;

    // TODO: Consider changing this to seastar::repeat and passing a stop toket to it
    // once the destructor of the class has been called.
    return do_until(
            [this] { return bool(_is_closing); },
            [this] {
                // std::cout << "In HTTP3 inside service_loop" << std::endl;

                return _channel_manager->read().then([this] (udp_datagram datagram) {
                    // std::cout << "In HTTP3 inside service_loop after read" << std::endl;

                    return handle_datagram(std::move(datagram));
                });
            }
    ).then([this] { return _channel_manager->close(); });
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::handle_datagram(udp_datagram&& datagram) {
    // std::cout << "In HTTP3 handle_datagram" << std::endl;

    quic_header_info header_info;

    const auto* fa = datagram.get_data().fragment_array();
    std::memcpy(_buffer.data(), fa->base, fa->size);

    connection_id key;

    const auto parse_header_result = quiche_header_info(
            reinterpret_cast<uint8_t*>(_buffer.data()),
            fa->size,
            sizeof(key._cid),
            &header_info.version,
            &header_info.type,
            header_info.scid.data,
            &header_info.scid.length,
            header_info.dcid.data,
            &header_info.dcid.length,
            header_info.token.data,
            &header_info.token.size
    );

    if (parse_header_result < 0) {
        // std::cout << "Failed to parse a QUIC header: " << parse_header_result << std::endl;
        return make_ready_future<>();
    }

    std::memcpy(key._cid, header_info.dcid.data, header_info.dcid.length);

    auto it = _connections.find(key);
    if (it == _connections.end()) {
        return handle_pre_hs_connection(header_info, std::move(datagram), key);
    } else {
        return handle_post_hs_connection(it->second, std::move(datagram));
    }
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::handle_post_hs_connection(lw_shared_ptr<connection_type> conn, udp_datagram&& datagram) {
    // std::cout << "In HTTP3 handle_post_hs_connection" << std::endl;

    conn->receive(std::move(datagram));
    conn->send_outstanding_data_in_streams_if_possible();
    return conn->quic_flush();
}

// TODO: Check if we cannot provide const references here instead.
template<template<typename> typename CT>
future<> quic_server_instance<CT>::handle_pre_hs_connection(quic_header_info& header_info, udp_datagram&& datagram, connection_id& key) {
    // std::cout << "In HTTP3 handle_pre_hs_connection" << std::endl;

    if (!quiche_version_is_supported(header_info.version)) {
        // std::cout << "Negotiating the version" << std::endl;

        return negotiate_version(header_info, std::move(datagram));
    }

    if (header_info.token.size == 0) {
        // std::cout << "Quic retry" << std::endl;

        return quic_retry(header_info, std::move(datagram));
    }

    // TODO: Refactor this
    const auto addr = datagram.get_src().as_posix_sockaddr();
    const auto* peer_addr = reinterpret_cast<const ::sockaddr_storage*>(&addr);
    const auto peer_addr_len = sizeof(addr);

    const auto local_addr = datagram.get_dst().as_posix_sockaddr();
    const auto local_addr_len = sizeof(local_addr);

    const bool validated_token = validate_token(
            header_info.token.data,
            header_info.token.size,
            peer_addr,
            peer_addr_len,
            reinterpret_cast<uint8_t*>(header_info.odcid.data),
            &header_info.odcid.length
    );

    if (!validated_token) {
        // std::cout << "Invalid address validation token." << std::endl;

        fmt::print(stderr, "Invalid address validation token.\n");
        return make_ready_future<>();
    }
    // std::cout << "token validated" << std::endl;
    quiche_conn* connection = quiche_accept(
            header_info.dcid.data,
            header_info.dcid.length,
            header_info.odcid.data,
            header_info.odcid.length,
            &local_addr,
            local_addr_len,
            &addr,
            peer_addr_len,
            _quiche_configuration.get_underlying_config()
    );

    if (connection == nullptr) {
        // std::cout << "Creating a connection has failed." << std::endl;

        fmt::print(stderr, "Creating a connection has failed.\n");
        return make_ready_future<>();
    }
    // std::cout << "Created a connection." << std::endl;

    auto conn = make_lw_shared<connection_type>(connection, this->weak_from_this(),
                                                datagram.get_src(), key);

//    conn->init();
// to be checked
    _waiting_queue.push(lw_shared_ptr(conn));
    // std::cout << "waiting queue: " << _waiting_queue.size()<< std::endl;

    // std::cout << "created and pushed connection" << std::endl;

    return handle_post_hs_connection(conn, std::move(datagram));
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::negotiate_version(const quic_header_info& header_info, udp_datagram&& datagram) {
    const auto written = quiche_negotiate_version(
            header_info.scid.data,
            header_info.scid.length,
            header_info.dcid.data,
            header_info.dcid.length,
            reinterpret_cast<uint8_t*>(_buffer.data()),
            _buffer.size()
    );

    if (written < 0) {
        // std::cout << "negotiate_version: failed to created a packet. Return value: " << written << std::endl;
        return make_ready_future<>();
    }

    quic_buffer qb{reinterpret_cast<quic_byte_type*>(_buffer.data()), static_cast<size_t>(written)};
    send_payload payload{std::move(qb), datagram.get_src()};

    return _channel_manager->send(std::move(payload));
}

template<template<typename> typename CT>
future<> quic_server_instance<CT>::quic_retry(const quic_header_info& header_info, udp_datagram&& datagram) {
    const auto addr = datagram.get_src().as_posix_sockaddr();
    const auto* peer_addr = reinterpret_cast<const ::sockaddr_storage*>(&addr);
    // TODO: Changing this to `datagram.get_src().length()`, which, to my understanding, should be
    // the right thing to do, causes validating the token return false later on. I think we should review
    // how exactly we use sizes of the address structs.
    const auto addr_len = sizeof(addr);

    const auto token = mint_token(header_info, peer_addr, addr_len);
    connection_id new_cid = generate_new_cid();

    const auto written = quiche_retry(
            header_info.scid.data,
            header_info.scid.length,
            header_info.dcid.data,
            header_info.dcid.length,
            new_cid._cid,
            sizeof(new_cid._cid),
            token.data,
            token.size,
            header_info.version,
            reinterpret_cast<uint8_t*>(_buffer.data()),
            _buffer.size()
    );

    if (written < 0) {
        // std::cout << "Failed to create a retry QUIC packet. Return value: " << written << std::endl;
        return make_ready_future<>();
    }

    quic_buffer qb{reinterpret_cast<quic_byte_type*>(_buffer.data()), static_cast<size_t>(written)};
    send_payload payload(std::move(qb), datagram.get_src());

    return _channel_manager->send(std::move(payload));
}

template<template<typename> typename CT>
connection_id quic_server_instance<CT>::generate_new_cid() {
    connection_id result;

    do {
        result = connection_id::generate();
    } while (_connections.find(result) != _connections.end());

    return result;
}


/// STATIC

template<template<typename> typename CT>
typename quic_server_instance<CT>::header_token quic_server_instance<CT>::mint_token(
            const quic_header_info& header_info, const ::sockaddr_storage* addr,
            ::socklen_t addr_len)
{
    header_token result;

    std::memcpy(result.data, "quiche", sizeof("quiche") - 1);
    std::memcpy(result.data + sizeof("quiche") - 1, addr, addr_len);
    std::memcpy(result.data + sizeof("quiche") - 1 + addr_len, header_info.dcid.data, header_info.dcid.length);

    result.size = sizeof("quiche") - 1 + addr_len + header_info.dcid.length;

    return result;
}

// TODO: Change this function to something proper, less C-like.
template<template<typename> typename CT>
bool quic_server_instance<CT>::validate_token(const uint8_t* token, size_t token_len, const ::sockaddr_storage* addr,
        ::socklen_t addr_len, uint8_t* odcid, size_t* odcid_len)
{
    if (token_len < sizeof("quiche") - 1 || std::memcmp(token, "quiche", sizeof("quiche") - 1) != 0) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if (token_len < addr_len || std::memcmp(token, addr, addr_len) != 0) {
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
        return false;
    }

    std::memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}



//========================
//........................
//........................
//. quic client instance .
//........................
//........................
//========================



template<template<typename> typename CT>
future<> quic_client_instance<CT>::send(send_payload&& payload) {
    return _channel_manager->send(std::move(payload));
}

template<template<typename> typename CT>
future<> quic_client_instance<CT>::handle_connection_closing(const connection_id& cid) {
    _closing_marker.mark();
    _channel_manager->abort_queues(std::make_exception_ptr(user_closed_connection_exception()));
    return _receive_fiber.handle_exception([this] (const std::exception_ptr& e) {
        return _channel_manager->close();
    });
}

template<template<typename> typename CT>
[[nodiscard]] connection_data quic_client_instance<CT>::connect(const socket_address& sa) {
    const socket_address la = _channel_manager->local_address();
    connection_id cid = connection_id::generate();

    auto* connection_ptr = quiche_connect(
            nullptr,    // TODO: Decide on the hostname
            cid._cid,
            sizeof(cid._cid),
            &la.as_posix_sockaddr(),
            la.length(),
            &sa.as_posix_sockaddr(),
            sa.length(),
            _quiche_configuration.get_underlying_config()
    );

    if (!connection_ptr) {
        throw std::runtime_error("Creating a QUIC connection has failed.");
    }

    return {.conn = connection_ptr, .id = cid, .pa = sa};
}

template<template<typename> typename CT>
void quic_client_instance<CT>::register_connection(lw_shared_ptr<connection_type> conn) {
    _connection = conn;
}

template<template<typename> typename CT>
void quic_client_instance<CT>::init() {
    _channel_manager->init();
    _receive_fiber = receive_loop();
}

// TODO: Ditch this.
template<template<typename> typename CT>
[[nodiscard]] std::string quic_client_instance<CT>::name() {
    return "client";
}

template<template<typename> typename CT>
future<> quic_client_instance<CT>::close() {
    return make_ready_future<>();
}

template<template<typename> typename CT>
future<> quic_client_instance<CT>::receive_loop() {
    return do_until(
            [this] { return bool(_closing_marker); },
            [this] { return receive(); }
    ).then([this] { return _channel_manager->close(); });
}

template<template<typename> typename CT>
future<> quic_client_instance<CT>::receive() {
    return _channel_manager->read().then([this](udp_datagram&& datagram) {
        _connection->receive(std::move(datagram));
        _connection->send_outstanding_data_in_streams_if_possible();
        return _connection->quic_flush();
    });
}



//========================
//........................
//........................
//... basic connection ...
//........................
//........................
//========================



template<typename QI>
void basic_connection<QI>::init() {
    _send_timer.set_callback([this] {
        (void) repeat([this] {
            if (_send_queue.empty()) {
                return make_ready_future<stop_iteration>(stop_iteration::yes);
            }

            const send_time_point now = send_clock::now();
            const send_time_point& send_time = _send_queue.top().get_time();

            if (send_time <= now + SEND_TIME_EPSILON) {
                // It is time to send the packet from the front of the queue.
                auto payload = std::move(_send_queue.fetch_top().payload);
                return _socket->send(std::move(payload)).then_wrapped([] (auto fut) {
                    if (!fut.failed()) {
                        return make_ready_future<stop_iteration>(stop_iteration::no);
                    }
                    fut.get_exception();
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                });
            } else {
                // No more packets should be sent now.
                _send_timer.rearm(send_time);
                return make_ready_future<stop_iteration>(stop_iteration::yes);
            }
        });
    });

    _timeout_timer.set_callback([this] {
        quiche_conn_on_timeout(_connection);
        if (is_closed()) {
            fmt::print("Conn is closed after on_timeout {}.\n", _socket->name());
            close();
            return;
        }
        (void) quic_flush();
    });

    // The client side of a connection ought to flush after initialization.
    (void) quic_flush();
}

template<typename QI>
void basic_connection<QI>::receive(udp_datagram&& datagram) {
    // std::cout << "in connection receive" << std::endl;
    auto* fa = datagram.get_data().fragment_array();
    auto pa = _peer_address.as_posix_sockaddr();
    auto la = _socket->local_address().as_posix_sockaddr();

    const quiche_recv_info recv_info = {
            .from       = &pa,
            .from_len   = sizeof(pa),
            .to         = &la,
            .to_len     = sizeof(la)
    };

    const auto recv_result = quiche_conn_recv(
            _connection,
            reinterpret_cast<uint8_t*>(fa->base),
            fa->size,
            &recv_info
    );
    // std::cout << "received sth: " << recv_result << std::endl;


    if (recv_result < 0) {
        // std::cout << "Failed to process a QUIC packet. Return value:" << recv_result << std::endl;

        fmt::print(stderr, "Failed to process a QUIC packet. Return value: {}\n", recv_result);
        return;
    }
    if (is_closed()) {
        // std::cout << "Conn is closed after receive" << std::endl;

        fmt::print("Conn is closed after receive {}.\n", _socket->name());
        close();
        return;
    }
    // std::cout << "in connection receive" << std::endl;

    if (quiche_conn_is_established(_connection)) {
        // std::cout << "in connection receive - connection established" << std::endl;
    }
    else {
        // std::cout << "in connection receive - connection not yet established" << std::endl;
    }

    if (_connect_done_promise && quiche_conn_is_established(_connection)) {
        _connect_done_promise->set_value();
        _connect_done_promise = std::nullopt;
    }

    if (quiche_conn_is_readable(_connection)) {
        fmt::print("SET READABLE.\n");
        _read_marker.mark_as_ready();
    }
    else {
        // std::cout << "conn not readable " << recv_result << std::endl;
    }
}

template<typename QI>
bool basic_connection<QI>::is_closed() const noexcept {
return quiche_conn_is_closed(_connection);
}

template<typename QI>
future<> basic_connection<QI>::quic_flush() {
    return repeat([this] {
        // Converts a time point stored as `timespec` to `send_time_point`.
        constexpr auto get_send_time = [](const timespec& at) constexpr -> send_time_point {
            return send_time_point(
                    std::chrono::duration_cast<send_time_duration>(
                            std::chrono::seconds(at.tv_sec) + std::chrono::nanoseconds(at.tv_nsec)
                    )
            );
        };

        quiche_send_info send_info;
        const auto written = quiche_conn_send(_connection, reinterpret_cast<uint8_t *>(_out_buffer.data()), _out_buffer.size(), &send_info);

        if (written == QUICHE_ERR_DONE) {
            return make_ready_future<stop_iteration>(stop_iteration::yes);
        }

        if (written < 0) {
            throw std::runtime_error("Failed to create a packet.");
        }

        quic_buffer qb{_out_buffer.data(), static_cast<size_t>(written)};
        send_payload payload{std::move(qb), send_info.to, send_info.to_len};

        const send_time_point send_time = get_send_time(send_info.at);

        if (_send_queue.empty() || send_time < _send_queue.top().get_time()) {
            _send_timer.rearm(send_time);
        }
        _send_queue.push(paced_payload{std::move(payload), send_time});

        return make_ready_future<stop_iteration>(stop_iteration::no);
    }).then([this] {
        if (_closing_marker) {
            return make_ready_future<>();
        }

        const auto timeout = static_cast<int64_t>(quiche_conn_timeout_as_millis(_connection));
        if (timeout >= 0) {
            _timeout_timer.rearm(timeout_clock::now() + std::chrono::milliseconds(timeout));
        }
        return make_ready_future<>();
    });
}

template<typename QI>
future<> basic_connection<QI>::ensure_closed() noexcept {
    return _ensure_closed_promise.get_future();
}

template<typename QI>
[[nodiscard]] socket_address basic_connection<QI>::remote_address() {
    return _peer_address;
}

template<typename QI>
future<> basic_connection<QI>::connect_done() {
    return _connect_done_promise->get_future();
}

template<typename QI>
connection_id basic_connection<QI>::cid() {
    return _connection_id;
}

template<typename QI>
bool basic_connection<QI>::is_closing() const noexcept {
    return quiche_conn_is_closed(_connection) || _closing_marker;
}



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
    _stream_recv_fiber = stream_recv_loop();
}

template<typename QI>
void quic_connection<QI>::close() {
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

    (void) do_with(this->shared_from_this(), [] (auto zis) {
        return zis->quic_flush().then([zis] {
            zis->_send_timer.cancel();
            zis->_timeout_timer.cancel();
            zis->_read_marker.mark_as_ready();
            fmt::print("Flushed after close.\n");
            for (auto &[key, stream] : zis->_streams) {
                stream.read_queue.abort(std::make_exception_ptr(std::runtime_error("Connection is closed.")));
            }

            return zis->_stream_recv_fiber.then([zis] {
                fmt::print("Closed stream rcv fiber.\n");
                return zis->_socket->handle_connection_closing(zis->_connection_id).then([zis] {
                    fmt::print("Socket handle connection finished.\n");
                    zis->_ensure_closed_promise.set_value();
                });
            });
        });
    });
}

template<typename QI>
future<> quic_connection<QI>::write(quic_buffer qb, quic_stream_id stream_id) {
    if (this->_closing_marker) {
        return make_exception_future<>(std::runtime_error("The connection has been closed."));
    }

    auto _stream = _streams.find(stream_id);
    if (_stream != _streams.end() && _stream->second.shutdown_output) {
        return make_exception_future<>(std::runtime_error("Output has been shutdown for a given stream.")); // TODO: custom exception?
    }

    const auto written = quiche_conn_stream_send(
            this->_connection,
            stream_id,
            reinterpret_cast<const uint8_t*>(qb.get()),
            qb.size(),
            false
    );

    if (written < 0) {
        // TODO: Handle the error.
        fmt::print("[Write] Writing to a stream has failed with message: {}\n", written);
    }

    const auto actually_written = static_cast<size_t>(written);

    if (actually_written != qb.size()) {
        qb.trim_front(actually_written);
        // TODO: Can a situation like this happen that Quiche keeps track
        // of a stream but we don't store it in the map? Investigate it.
        // In such a case, we should catch an exception here and report it.
        auto& stream = _streams[stream_id];
        stream.write_queue.push_front(std::move(qb));
    }

    return this->quic_flush().then([stream_id, this] () {
        return wait_send_available(stream_id);
    });
}

template<typename QI>
future<quic_buffer> quic_connection<QI>::read(quic_stream_id stream_id) {
    if (this->_closing_marker) {
        // EOF
        return make_ready_future<quic_buffer>(temporary_buffer<char>("", 0));
    }

    auto &stream = _streams[stream_id];
    return stream.read_queue.pop_eventually().then_wrapped([] (auto fut) {
       if (fut.failed()) {
           fut.get_exception();
           return make_ready_future<quic_buffer>(temporary_buffer<char>("", 0));
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
                // TODO: Handle quiche error.
                fmt::print("[Send outstanding] Writing to a stream has failed with message: {}\n", written);
            }

            const auto actually_written = static_cast<size_t>(written);

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

    stream.write_queue.clear();
    stream.shutdown_output = true;
    if (stream.maybe_writable) {
        stream.maybe_writable->set_exception(std::runtime_error("Output has been shutdown on the given stream."));
        stream.maybe_writable = std::nullopt;
    }

    if (quiche_conn_stream_send(this->_connection, stream_id, nullptr, 0, true) < 0) {
        throw std::runtime_error("Unexpected quiche_conn_stream_send error");
    }
    if (quiche_conn_stream_shutdown(this->_connection, stream_id, QUICHE_SHUTDOWN_WRITE, 0)) {
        throw std::runtime_error("Unexpected quiche_conn_stream_shutdown error");
    }

    (void) this->quic_flush();
}

template<typename QI>
future<> quic_connection<QI>::stream_recv_loop() {
    return do_until([this] { return this->is_closing(); }, [this] {
        return this->_read_marker.get_shared_future().then([this] {
            quic_stream_id stream_id;
            auto iter = quiche_conn_readable(this->_connection);

            while (quiche_stream_iter_next(iter, &stream_id)) {
                auto& stream = _streams[stream_id];

                // TODO for danmas: think about it
                if (quiche_conn_stream_finished(this->_connection, stream_id)) {
                    stream.read_queue.push(temporary_buffer<char>("", 0));
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
                        fmt::print(stderr, "Reading from a stream has failed with message: {}\n", recv_result);
                    } else {
                        quic_buffer message{this->_buffer.data(), static_cast<size_t>(recv_result)};
                        // TODO: Wrap this in some kind of `not_full` future
                        // (or just read only when necessary).
                        // TODO2: Learn more about exceptions that might be thrown here.
                        stream.read_queue.push(std::move(message));
                    }
                }
            }

            quiche_stream_iter_free(iter);

            if (!quiche_conn_is_readable(this->_connection)) {
                fmt::print("Read marker reset.\n");
                this->_read_marker.reset();
            }
            else {
                fmt::print("READABLE?\n");
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



//========================
//........................
//........................
//.... h3 connection .....
//........................
//........................
//========================

template<typename QI>
void h3_connection<QI>::init() {
    super_type::init();
    qlogger.info("Initializing HTTP3 connection.");

    // std::cout << "initializing h3_connection" << std::endl;
    h3_config = quiche_h3_config_new();
    if (h3_config == nullptr) {
        // std::cout << "failed to create HTTP/3 config:" << std::endl;
    }
    else         // std::cout << "created HTTP/3 config:" << std::endl;

//    if (_h3_conn == NULL) {
//        _h3_conn = quiche_h3_conn_new_with_transport(this->_connection, h3_config);
//        if (_h3_conn == NULL) {
//            // std::cout << "failed to create HTTP/3 connection:" << std::endl;        }
//    }
    _stream_recv_fiber = this->connect_done().then([this] {
        if (_h3_conn == nullptr) {
            qlogger.info("Created new HTTP3 connection");
            _h3_conn = quiche_h3_conn_new_with_transport(this->_connection, h3_config);
            if (_h3_conn == nullptr) {
                qlogger.error("Failed to create new HTTP3 connection");
            }
            _h3_connect_done_promise.set_value();
        }
        return seastar::make_ready_future<>();
    }).then([this] {
        return h3_recv_loop();
    });
}

template<typename QI>
void h3_connection<QI>::close() {

    std::cout << "calling h3_connection close" << std::endl;
    return; // FOR SOME REASON, THE H3 CONNECTION IS GETTING CLOSED.
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
    // TODO
}

template<typename QI>
future<std::unique_ptr<quic_h3_request>> h3_connection<QI>::read() {
    if (this->_closing_marker) {
        // EOF
        return make_ready_future<std::unique_ptr<quic_h3_request>>();
    }

    // std::cout << "H3_connection socket read: " << read_queue.size() << std::endl;
    return read_queue.pop_eventually().then([] (auto fut) {
        // std::cout << "H3_connection socket read popped" << std::endl;
// TODO
//        if (fut.failed()) { // ?
//            // std::cout << "H3_connection socket read FAILED" << std::endl;
//
//            fut.get_exception();
//            return make_ready_future<std::unique_ptr<quic_h3_request>>();
//        }
        return fut;
    });
}

template<typename QI>
future<> h3_connection<QI>::h3_recv_loop() {
    // std::cout << "H3_connection socket recv_loop" << std::endl;
    qlogger.info("Staring HTTP3 receive loop");
    return do_until([this] {
        return this->is_closing(); }, [this] {
        // std::cout << "H3_connection socket recv_loop ENTERING" << std::endl;
        return this->_read_marker.get_shared_future().then([this] {
            qlogger.info("Reading marker says there's something to read.");
            // std::cout << "H3_connection socket recv_loop ENTERED" << std::endl;

            if (quiche_conn_is_established(this->_connection)) {
                // std::cout << "H3_connection socket recv_loop ESTABLISHED" << std::endl;

                if (_h3_conn == nullptr) {
                    qlogger.error("The connection should be created at this point!");
                }

                quiche_h3_event *ev;

                int64_t s = quiche_h3_conn_poll(_h3_conn, this->_connection, &ev);
                if (s < 0) {
                    qlogger.info("Not readable, s: {}, skipping", s);
                    goto spaghetti_code_dont_kill_me;
                }
                auto new_req = std::make_unique<seastar::net::quic_h3_request>();
                new_req->_stream_id = s;
                qlogger.info("Got request on stream {}", s);
                switch (quiche_h3_event_type(ev)) {
                    case QUICHE_H3_EVENT_HEADERS: {
                        fmt::print("QUICHE_H3_EVENT_HEADERS\n");


                        int rc = quiche_h3_event_for_each_header(ev, for_each_header,
                                                                 new_req.get());

                        if (rc != 0) {
                            fprintf(stderr, "failed to process headers");
                        }
                        break;
                    }

                    case QUICHE_H3_EVENT_DATA: {
                        fmt::print("QUICHE_H3_EVENT_DATA\n");
                        static uint8_t buf[MAX_DATAGRAM_SIZE];

                        ssize_t len = quiche_h3_recv_body(_h3_conn, this->_connection, s, buf, sizeof(buf));

                        if (len <= 0) {
                            break;
                        }
//                        printf("GOT: %.*s", (int) len, buf);

                        new_req->_req.content_length = len;
                        new_req->_req.content = to_sstring(buf);
                        break;
                    }

                    case QUICHE_H3_EVENT_FINISHED:
                        fmt::print("QUICHE_H3_EVENT_FINISHED\n");
                        break;

                    case QUICHE_H3_EVENT_RESET:
                        fmt::print("QUICHE_H3_EVENT_RESET\n");
                        break;

                    case QUICHE_H3_EVENT_PRIORITY_UPDATE:
                        fmt::print("QUICHE_H3_EVENT_PRIORITY_UPDATE\n");
                        break;

                    case QUICHE_H3_EVENT_DATAGRAM:
                        fmt::print("QUICHE_H3_EVENT_DATAGRAM\n");
                        break;

                    case QUICHE_H3_EVENT_GOAWAY: {
                        fmt::print("QUICHE_H3_EVENT_GOAWAY\n");
                        break;
                    }
                }
                read_queue.push(std::move(new_req));
                quiche_h3_event_free(ev);

            }
            else {
                // std::cout << "H3_connection socket recv_loop NOT ESTABLISHED" << std::endl;

            }

            spaghetti_code_dont_kill_me:
            if (!quiche_conn_is_readable(this->_connection)) {
                fmt::print("Read marker reset.\n");
                this->_read_marker.reset();
            }
            else {
                fmt::print("READABLE?\n");
            }

            return this->quic_flush();
        });
    }).then([] {
       qlogger.info("Ending HTTP3 receive loop.");
    });
}

template<typename QI>
future<> h3_connection<QI>::write(std::unique_ptr<quic_h3_reply> reply) {
    if (this->_closing_marker) {
        return make_exception_future<>(std::runtime_error("The connection has been closed."));
    }

    std::vector<quiche_h3_header> headers;

    quiche_h3_header status = {
            .name = (const uint8_t *) ":status",
            .name_len = sizeof(":status") - 1,

            .value = reinterpret_cast<const uint8_t *>("200"),
            .value_len = 3
    };
    headers.push_back(status);

    for (const auto& h : reply->_resp._headers) {
        std::cout << "Header: " << h.first << ", value: " << h.second << std::endl;
        headers.push_back({
                                  .name = (const uint8_t *) h.first.c_str(),
                                  .name_len = h.first.size(),

                                  .value = (const uint8_t *) h.second.c_str(),
                                  .value_len = h.second.size(),
                          });
    }


    quiche_h3_send_response(_h3_conn, this->_connection,
                            reply->_stream_id, headers.data(), headers.size(), false);

    const auto written = quiche_h3_send_body(_h3_conn, this->_connection,
                                             reply->_stream_id, (uint8_t *) reply->_resp._content.c_str(), reply->_resp.content_length, true);

    if (written < 0) {
        // TODO: Handle the error.
        fmt::print("[Write] Writing to a stream has failed with message: {}\n", written);
    }

    // TODO bufor
    const auto actually_written = static_cast<size_t>(written);

    if (actually_written != reply->_resp.content_length) {

    }

    return this->quic_flush().then([] () {
//        return wait_send_available(); //TODO
        return seastar::make_ready_future<>();
    });

}

template<typename QI>
void h3_connection<QI>::send_outstanding_data_in_streams_if_possible() {
    // std::cout << "send_outstanding_data_in_streams_if_possible" << std::endl;
    auto& queue = write_queue;

    while (!queue.empty()) {
        // std::cout << "send_outstanding_data_in_streams_if_possible: queue was not empty" << std::endl;

        auto qb = std::move(queue.front());
        queue.pop_front();
        //TODO to be finished properly
//                const auto written = quiche_conn_stream_send(
//                        this->_connection,
//                        stream_id,
//                        reinterpret_cast<const uint8_t*>(qb.get()),
//                        qb.size(),
//                        false
//                );
//
//                if (written < 0) {
//                    // TODO: Handle quiche error.
//                    fmt::print("[Send outstanding] Writing has failed with message: {}\n", written);
//                }
//
//                const auto actually_written = static_cast<size_t>(written);
//
//                if (actually_written != qb.size()) {
//                    qb.trim_front(actually_written);
//                    queue.push_front(std::move(qb));
//                    break;
//                }
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
using h3_server   = quic_server_instance<h3_connection>;

using quic_server_connection = quic_connection<quic_server>;
using quic_client_connection = quic_connection<quic_client>;
using h3_server_connection   = h3_connection<h3_server>;

using quic_engine_type = quic_engine<quic_server, quic_client, h3_server>;



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

lw_shared_ptr<h3_server> h3_listen(const socket_address& sa,
                                   const std::string_view cert_file, const std::string_view cert_key,
                                   const quic_connection_config& quic_config, const size_t queue_length = 100)
{
    auto instance = make_lw_shared<h3_server>(
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


class quiche_stream_server_socket_impl final : public quic_server_socket_impl {
// Local definitions.
private:
    using implementation_type = quiche_quic_connected_socket_impl<quic_server_connection>;

// Fields.
private:
    lw_shared_ptr<quic_server> _listener;

// Constructors + the destructor.
public:
    quiche_stream_server_socket_impl(const socket_address& sa, const std::string_view cert_file,
            const std::string_view cert_key, const quic_connection_config& quic_config)
    : _listener(quiche_listen(sa, cert_file, cert_key, quic_config)) {}

    ~quiche_stream_server_socket_impl() = default;

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
        // std::cout << "In HTTP3 impl accept" << std::endl;

        return _listener->accept().then([] (lw_shared_ptr<h3_server_connection> conn) {
            future <> h3_connected = conn->_h3_connect_done_promise.get_future();
            return h3_connected.then([conn] {
                auto impl = std::make_unique<implementation_type>(conn);
                qlogger.info("Accepted new H3 connection");
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


quic_server_socket quic_listen(const socket_address& sa, const std::string_view cert_file,
        const std::string_view cert_key, const quic_connection_config& quic_config)
{
    return quic_server_socket(std::make_unique<quiche_stream_server_socket_impl>(sa, cert_file, cert_key, quic_config));
}

quic_h3_server_socket quic_h3_listen(const socket_address& sa, const std::string_view cert_file,
                                     const std::string_view cert_key, const quic_connection_config& quic_config)
{
    // std::cout << "\n QUIC h3 listen" << std::endl;

    return quic_h3_server_socket(std::make_unique<quiche_h3_server_socket_impl>(sa, cert_file, cert_key, quic_config));
}

future<quic_connected_socket> quic_connect(const socket_address& sa,
        const quic_connection_config& quic_config)
{
    using impl_type = quiche_quic_connected_socket_impl<quic_client_connection>;

    try {
        auto connection = quiche_connect(sa, quic_config);
        return connection->connect_done().then([connection = connection] {
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

future<std::unique_ptr<quic_h3_request>> quic_h3_connected_socket:: read() {
    // std::cout << "H3 socket read" << std::endl;

    return future<std::unique_ptr<quic_h3_request>>(_impl->read());
}

future<> quic_h3_connected_socket::write(std::unique_ptr<quic_h3_reply> reply) {
    // std::cout << "H3 socket write" << std::endl;

    return future<>(_impl->write(std::move(reply)));
}

void quic_enable_logging() {
    quiche_enable_debug_logging(quiche_log_printer, nullptr);
}

} // namespace seastar::net
