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
 * Copyright (C) 2015 Cloudius Systems, Ltd.
 */

// Demonstration of ability to receive big chunks of data.

#include <seastar/core/app-template.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/future-util.hh>
#include <seastar/net/api.hh>
#include <seastar/net/quic.hh>
#include <seastar/core/sleep.hh>

constexpr static std::uint64_t STREAM_ID = 4;

static size_t rcv_bytes = 0;

seastar::future<> handle_connection(seastar::net::quic_accept_result accept_result) {
    std::cout << "Accepted connection!" << std::endl;
    auto conn = std::move(accept_result.connection);
    auto in = conn.input(STREAM_ID);
    return seastar::do_with(std::move(conn), std::move(in), [](auto &conn, auto &in) {
        return seastar::keep_doing([&in]() {
            return in.read().then([](seastar::temporary_buffer<char> buf) {
                rcv_bytes += buf.size();
                std::cout << "Received " << buf.size() << " bytes, total " << (double) rcv_bytes / 1000000.0 << "MB" << std::endl;
                return seastar::make_ready_future();
            });
        });
    });
}

seastar::future<> service_loop() {
    // TODO: Either add keys to the repo or generate them here.
    std::string cert_file = "/home/danielmastalerz/Pulpit/seastar_quic/quiche/quiche/examples/cert.crt";
    std::string key_file = "/home/danielmastalerz/Pulpit/seastar_quic/quiche/quiche/examples/cert.key";

    return seastar::do_with(seastar::net::quic_listen(seastar::make_ipv4_address({1234}), cert_file, key_file),
                            [](auto &listener) {
                                return seastar::keep_doing([&listener]() {
                                    return listener.accept().then([](seastar::net::quic_accept_result result) {
                                        (void) handle_connection(std::move(result));
                                    });
                                });
                            });
}

int main(int ac, char **av) {
    seastar::app_template app;
    return app.run(ac, av, service_loop);
}
