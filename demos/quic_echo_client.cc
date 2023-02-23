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
#include <seastar/core/thread.hh>
#include "seastar/core/sleep.hh"

constexpr static std::uint64_t STREAM_NUM = 100;

using namespace std::chrono_literals;


seastar::input_stream<char> arr1[STREAM_NUM];
seastar::output_stream<char> arr2[STREAM_NUM];

seastar::future<> service_loop() {
    return seastar::net::quic_connect(seastar::make_ipv4_address({1234}))
            .then([](seastar::net::quic_connected_socket conn) {
                std::cout << "Connected!" << std::endl;
                int start = 4;
                for (std::uint64_t i = 0; i < STREAM_NUM; i++) {
                    arr1[i] = conn.input(start);
                    arr2[i] = conn.output(start);
                    start += 4;
                }

                return seastar::do_with(std::move(conn), std::move(arr1), std::move(arr2),
                                        [](auto &conn, auto &arr1, auto &arr2) {
                                            return seastar::keep_doing([&arr1, &arr2]() {
                                                return seastar::async([&] {
                                                    auto client_write = seastar::async([&] {
                                                        for (std::uint64_t j = 0; j < STREAM_NUM; j++) {
                                                            seastar::sleep(1s).get();
                                                            std::string msg =
                                                                    "Hello from client " + std::to_string(j);
                                                            arr2[j].write(msg).get();
                                                            arr2[j].flush().get();
                                                            std::cout << "Sent message. " << j << std::endl;
                                                        }
                                                    });

                                                    auto client_read = seastar::async([&] {
                                                        for (std::uint64_t j = 0; j < STREAM_NUM; j++) {
                                                            auto buf = arr1[j].read().get();
                                                            char msg_buf[buf.size() + 1];
                                                            memcpy(msg_buf, buf.get(), buf.size());
                                                            msg_buf[buf.size()] = '\0';
                                                            std::cout << "Received message: "
                                                                      << msg_buf << " " << j
                                                                      << std::endl;
                                                        }
                                                    });

                                                    when_all(std::move(client_write),
                                                             std::move(client_read)).discard_result().get();

                                                });
                                            });
                                        });
            });
}

int main(int ac, char **av) {
    seastar::app_template app;
    return app.run(ac, av, service_loop);
}
