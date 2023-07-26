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
#include <seastar/core/future-util.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/net/api.hh>
#include <seastar/net/inet_address.hh>
#include <seastar/net/quic.hh>

namespace bpo = boost::program_options;
using namespace std::chrono_literals;

seastar::future<> service_loop(const uint16_t port, const std::string address) {
    constexpr static uint64_t STREAM_ID = 4;
    static uint64_t msg_id = 0;

    return seastar::net::quic_connect(
        { seastar::net::inet_address(address), port }
    ).then([] (seastar::net::quic_connected_socket conn) {
        std::cout << "Connected!" << std::endl;

        auto in = conn.input(STREAM_ID);
        auto out = conn.output(STREAM_ID);

        return seastar::do_with(std::move(conn), std::move(in), std::move(out), [] (auto& conn, auto& in, auto& out) {
            return seastar::keep_doing([&in, &out] {
                return seastar::sleep(1s).then([&in, &out] {
                    std::string msg = "Hello from client " + std::to_string(msg_id++);
                    return out.write(msg).then([&in, &out] {
                        return out.flush().then([&in] {
                            std::cout << "Sent message." << std::endl;
                            return in.read().then([] (seastar::temporary_buffer<char> buf) {
                                const auto msg = std::string_view{buf.begin(), buf.size()};
                                std::cout << "Received message: " << msg << std::endl;
                                return seastar::make_ready_future();
                            });
                        });
                    });
                });
            });
        });
    });
}

int main(int ac, char** av) {
    seastar::app_template app;
    app.add_options()
            ("port", bpo::value<uint16_t>()->default_value(1234), "Server port")
            ("address", bpo::value<std::string>()->default_value("127.0.0.1"), "Server IP address");

    return app.run(ac, av, [&] {
        auto&& config = app.configuration();
        auto port = config["port"].as<uint16_t>();
        auto address = config["address"].as<std::string>();
        return service_loop(port, address);
    });
}
