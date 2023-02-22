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
 * Copyright (C) 2019 Elazar Leibovich
 */

#include <seastar/core/reactor.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/app-template.hh>
#include <seastar/core/print.hh>
#include <seastar/core/memory.hh>
#include <seastar/util/std-compat.hh>
#include <seastar/util/later.hh>
#include <seastar/testing/test_case.hh>
#include <seastar/core/abort_source.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/thread.hh>
#include <seastar/core/when_all.hh>

#include <seastar/net/posix-stack.hh>
#include <seastar/net/quic.hh>

using namespace seastar;

constexpr static std::uint64_t STREAM_ID = 4;

std::string cert_file = "/home/julias/mim/zpp/seastar-master/quiche/quiche/examples/cert.crt";
std::string key_file = "/home/julias/mim/zpp/seastar-master/quiche/quiche/examples/cert.key";

//future<> handle_connection(accept_result ar) {
//    auto s = std::move(ar.connection);
//    auto in = s.input();
//    auto out = s.output();
//    return do_with(std::move(in), std::move(out), [](auto& in, auto& out) {
//        return do_until([&in]() { return in.eof(); },
//                        [&in, &out] {
//                            return in.read().then([&out](auto buf) {
//                                char msg_buf[buf.size() + 1];
//                                memcpy(msg_buf, buf.get(), buf.size());
//                                msg_buf[buf.size()] = '\0';
//                                std::cout << "Received message: " << msg_buf << std::endl;
//                                return out.write(std::move(buf)).then([&out]() { return out.close(); });
//                            });
//                        });
//    });
//}

future<> handle_connection(seastar::net::quic_accept_result ar) {
    auto s = std::move(ar.connection);
    auto in = s.input(STREAM_ID);
    auto out = s.output(STREAM_ID);
    return do_with(std::move(s), std::move(in), std::move(out), [](auto &conn, auto &in, auto &out) {
        return do_until([&in]() { return in.eof(); },
                        [&in, &out] {
                            std::cout << "Receiving " << std::endl;
                            // in.read() should get eof and return an empty buffer, instead it waits infinitely for the msg
                            return in.read().then([&out](auto buf) {
                                char msg_buf[buf.size() + 1];
                                memcpy(msg_buf, buf.get(), buf.size());
                                msg_buf[buf.size()] = '\0';
                                std::cout << "Received message: " << msg_buf << std::endl;
                                return out.write(std::move(buf)).then([&out]() { return out.close(); });
                            });
                        });
    });
}

// handle_connection from echo_server
//seastar::future<> handle_connection(seastar::net::quic_accept_result accept_result) {
//    std::cout << "Accepted connection!" << std::endl;
//    auto conn = std::move(accept_result.connection);
//    auto in = conn.input(STREAM_ID);
//    auto out = conn.output(STREAM_ID);
//    return seastar::do_with(std::move(conn), std::move(in), std::move(out), [](auto &conn, auto &in, auto &out) {
//        return seastar::keep_doing([&in, &out]() {
//            return in.read().then([&out](seastar::temporary_buffer<char> buf) {
//                char msg_buf[buf.size() + 1];
//                memcpy(msg_buf, buf.get(), buf.size());
//                msg_buf[buf.size()] = '\0';
//                std::cout << "Received message: " << msg_buf << std::endl;
//                return out.write(std::move(buf)).then([&out]() {
//                    return out.flush();
//                });
//            });
//        });
//    });
//}

//future<> echo_server_loop() {
//    return do_with(
//            server_socket(listen(make_ipv4_address({1234}), listen_options{.reuse_address = true})), [](auto& listener) {
//                // Connect asynchronously in background.
//                (void)connect(make_ipv4_address({"127.0.0.1", 1234})).then([](connected_socket&& socket) {
//                    socket.shutdown_output();
//                });
//                return listener.accept().then(
//                        [](accept_result ar) {
////                            connected_socket s = std::move(ar.connection);
//                            return handle_connection(std::move(ar));
//                        }).then([l = std::move(listener)]() mutable {
//                            fmt::print("endddd\n");
//                            return l.abort_accept(); });
//            });
//}

future<> echo_server_loop() {
    return do_with(
            net::quic_server_socket(net::quic_listen(make_ipv4_address({1234}), cert_file, key_file)),
            [](auto &listener) {
                // Connect asynchronously in background.
                (void) net::quic_connect(make_ipv4_address({"127.0.0.1", 1234})).then(
                        [](net::quic_connected_socket &&socket) {
                            // should block the client output so the server doesn't wait
                            socket.shutdown_output();
                        });
                return listener.accept().then(
                        [](net::quic_accept_result ar) {
                            std::cout << "accepted " << std::endl;
//                            net::quic_connected_socket s = std::move(ar.connection);
                            return handle_connection(std::move(ar));
                        }).then([l = std::move(listener)]() mutable {
                    fmt::print("endddd\n");
                    return l.abort_accept();
                });
            });
}

class my_malloc_allocator : public std::pmr::memory_resource {
public:
    int allocs;
    int frees;

    void *do_allocate(std::size_t bytes, std::size_t alignment) override {
        allocs++;
        return malloc(bytes);
    }

    void do_deallocate(void *ptr, std::size_t bytes, std::size_t alignment) override {
        frees++;
        return free(ptr);
    }

    virtual bool do_is_equal(const std::pmr::memory_resource &__other) const noexcept override { abort(); }
};

my_malloc_allocator malloc_allocator;
std::pmr::polymorphic_allocator<char> allocator{&malloc_allocator};

//SEASTAR_TEST_CASE(socket_allocation_test) {
//    return echo_server_loop().finally(
//            []() { engine().exit((malloc_allocator.allocs == malloc_allocator.frees) ? 0 : 1); });
//}

// original test with seastar::socket
//SEASTAR_TEST_CASE(socket_skip_test) {
//    return seastar::async([&] {
//        listen_options lo;
//        lo.reuse_address = true;
//        server_socket ss = listen(ipv4_addr("127.0.0.1", 1234), lo);
//
//        abort_source as;
//        auto client = async([&as] {
//            connected_socket socket = connect(ipv4_addr("127.0.0.1", 1234)).get();
//            socket.output().write("abc").get();
//            socket.shutdown_output();
//            try {
//                sleep_abortable(std::chrono::seconds(10), as).get();
//            } catch (const sleep_aborted &) {
//                // expected
//                return;
//            }
//            assert(!"Skipping data from socket is likely stuck");
//        });
//
//        accept_result accepted = ss.accept().get();
//        input_stream<char> input = accepted.connection.input();
//        input.skip(16).get();
//        as.request_abort();
//        client.get();
//    });
//}

//SEASTAR_TEST_CASE(socket_skip_test) {
//    return seastar::async([&] {
//
//        net::quic_server_socket ss = net::quic_listen(ipv4_addr("127.0.0.1", 1234), cert_file, key_file);
//        abort_source as;
//        auto client = async([&as] {
//            net::quic_connected_socket socket = net::quic_connect(ipv4_addr("127.0.0.1", 1234)).get();
//            socket.output(STREAM_ID).write("abc").get();
//            socket.shutdown_output(); // function to be implemented correctly
//            try {
//                sleep_abortable(std::chrono::seconds(10), as).get();
//            } catch (const sleep_aborted &) {
//                // expected
//                return;
//            }
//            assert(!"Skipping data from socket is likely stuck");
//        });
//
//        net::quic_accept_result accepted = ss.accept().get();
//        input_stream<char> input = accepted.connection.input(STREAM_ID);
//        input.skip(16).get(); // doesn't finish correctly without a properly shut down client
//        as.request_abort();
//        client.get(); // assertion `!_end && !_zc_bufs && "Was this stream properly closed?"' failed
//        // in ~output_stream()
//    });
//}

SEASTAR_TEST_CASE(test_file_desc_fdinfo) {
    auto fd = file_desc::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    auto info = fd.fdinfo();
    BOOST_REQUIRE_EQUAL(info.substr(0, 8), "socket:[");
    return make_ready_future<>();
}

// BOOST_REQUIRE_EQUAL failing
//SEASTAR_TEST_CASE(socket_on_close_test) {
//    return seastar::async([&] {
//        listen_options lo;
//        lo.reuse_address = true;
//        net::quic_server_socket ss = net::quic_listen(ipv4_addr("127.0.0.1", 12345), cert_file, key_file);
//        bool server_closed = false;
//        bool client_notified = false;
//
//        auto client = seastar::async([&] {
//            net::quic_connected_socket cln = net::quic_connect(ipv4_addr("127.0.0.1", 12345)).get0();
//
//            auto close_wait_fiber = cln.wait_input_shutdown().then([&] {
//                BOOST_REQUIRE_EQUAL(server_closed, true); // failing to close server
//                // - should wait_input_shutdown somehow alter the value?
//                client_notified = true;
//                fmt::print("Client: server closed\n");
//            });
//
//            auto out = cln.output(STREAM_ID);
//            auto in = cln.input(STREAM_ID);
//
//            // client not finishing properly
//            while (!client_notified) {
//                fmt::print("Client: -> message\n");
//                out.write("hello").get();
//                out.flush().get();
//                seastar::sleep(std::chrono::milliseconds(250)).get();
//                fmt::print("Client: <- message\n");
//                auto buf = in.read().get0();
//                if (!buf) {
//                    fmt::print("Client: server eof\n");
//                    break;
//                }
//                seastar::sleep(std::chrono::milliseconds(250)).get();
//            }
//
//            out.close().get();
//            in.close().get();
//            close_wait_fiber.get();
//        });
//
//        auto server = seastar::async([&] {
//            net::quic_accept_result acc = ss.accept().get0();
//            auto out = acc.connection.output(4);
//            auto in = acc.connection.input(4);
//
//            for (int i = 0; i < 3; i++) {
//                auto buf = in.read().get();
//                BOOST_REQUIRE_EQUAL(client_notified, false);
//                out.write(std::move(buf)).get();
//                out.flush().get();
//                fmt::print("Server: served\n");
//            }
//
//            server_closed = true;
//            fmt::print("Server: closing\n");
//            out.close().get();
//            in.close().get();
//        });
//
//        when_all(std::move(client), std::move(server)).discard_result().get();
//    });
//}

// finishes but failing with exit code 1
SEASTAR_TEST_CASE(socket_on_close_local_shutdown_test) {
    return seastar::async([&] {

        net::quic_server_socket ss = net::quic_listen(ipv4_addr("127.0.0.1", 12345), cert_file, key_file);

        bool server_closed = false;
        bool client_notified = false;

        auto client = seastar::async([&] {
            net::quic_connected_socket cln = net::quic_connect(ipv4_addr("127.0.0.1", 12345)).get0();

            auto close_wait_fiber = cln.wait_input_shutdown().then([&] {
                BOOST_REQUIRE_EQUAL(server_closed, false);
                client_notified = true;
                fmt::print("Client: socket closed\n");
            });

            auto out = cln.output(STREAM_ID);
            cln.shutdown_input();

            auto fin = std::chrono::steady_clock::now() + std::chrono::seconds(1);
            do {
                seastar::yield().get();
            } while (!client_notified && std::chrono::steady_clock::now() < fin);
            BOOST_REQUIRE_EQUAL(client_notified, true);

            out.write("hello").get();
            out.flush().get();
            out.close().get();

            close_wait_fiber.get();
        });

        auto server = seastar::async([&] {
            net::quic_accept_result acc = ss.accept().get0();
            auto in = acc.connection.input(STREAM_ID);
            auto buf = in.read().get();
            server_closed = true;
            fmt::print("Server: closing\n");
            in.close().get();
        });

        when_all(std::move(client), std::move(server)).discard_result().get();
    });
}
