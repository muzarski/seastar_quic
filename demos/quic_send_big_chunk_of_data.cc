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

// Demonstration of ability to send big chunks of data. Shows the ability to buffer the data, like in TCP.

#include <seastar/core/app-template.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/future-util.hh>
#include <seastar/net/api.hh>
#include <seastar/net/quic.hh>
#include "seastar/core/sleep.hh"

constexpr static std::uint64_t STREAM_ID = 4;
constexpr static std::uint64_t HUNDRED_MEGABYTES = 1000 * 1000 * 100;

using namespace std::chrono_literals;

static char buf[HUNDRED_MEGABYTES];

seastar::future<> service_loop() {
    return seastar::net::quic_connect(seastar::make_ipv4_address({1234}))
            .then([](seastar::net::quic_connected_socket conn) {
                std::cout << "Connected!" << std::endl;
                auto out = conn.output(STREAM_ID);
                return seastar::do_with(std::move(conn), std::move(out),
                                        [](auto &conn, auto &out) {
                                            return out.write(buf, HUNDRED_MEGABYTES).then([]() {
                                                // TODO: when flush is implemented, then flush
                                                // right now, not all the data is being sent
                                                // because the app is able to send again before the whole
                                                // buffer is actually sent, and the program ends.
                                                std::cout << "Able to send again!" << std::endl;
                                            }).then([&conn] () {
                                               return conn.close(); 
                                            });
                                        });
            });
}

int main(int ac, char **av) {
    seastar::app_template app;
    return app.run(ac, av, service_loop);
}
