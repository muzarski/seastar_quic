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

// Demonstration of ability to connect to QUIC server, send data to it, and receive the response.

#include <seastar/core/app-template.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/future-util.hh>
#include <seastar/net/api.hh>
#include <seastar/net/quic.hh>
#include "seastar/core/sleep.hh"

constexpr static std::uint64_t STREAM_ID = 4;
static std::uint64_t msg_id = 0;

using namespace std::chrono_literals;

seastar::future<> service_loop() {
    return seastar::net::quic_connect(seastar::make_ipv4_address({1234}))
            .then([](seastar::net::quic_connected_socket conn) {
                std::cout << "Connected!" << std::endl;
                auto in = conn.input(STREAM_ID);
                auto out = conn.output(STREAM_ID);
                return seastar::do_with(std::move(conn), std::move(in), std::move(out),
                                        [](auto &conn, auto &in, auto &out) {
                                            return seastar::keep_doing([&in, &out]() {
                                                return seastar::sleep(1s).then([&in, &out]() {
                                                    std::string msg = "Hello from client " + std::to_string(msg_id++);
                                                    return out.write(msg).then([&in, &out]() {
                                                        return out.flush().then([&in]() {
                                                            std::cout << "Sent message." << std::endl;
                                                            return in.read().then(
                                                                    [](seastar::temporary_buffer<char> buf) {
                                                                        char msg_buf[buf.size() + 1];
                                                                        memcpy(msg_buf, buf.get(), buf.size());
                                                                        msg_buf[buf.size()] = '\0';
                                                                        std::cout << "Received message: " << msg_buf
                                                                                  << std::endl;
                                                                        return seastar::make_ready_future();
                                                                    });
                                                        });
                                                    });
                                                });
                                            });
                                        });
            });
}

int main(int ac, char **av) {
    seastar::app_template app;
    return app.run(ac, av, service_loop);
}
