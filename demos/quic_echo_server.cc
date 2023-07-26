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

// Demonstration of ability to accept QUIC connection and echo-ing the received data.

#include <seastar/core/app-template.hh>
#include <seastar/core/future-util.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/net/api.hh>
#include <seastar/net/inet_address.hh>
#include <seastar/net/quic.hh>

#include <string_view>

namespace bpo = boost::program_options;

constexpr static std::uint64_t STREAM_ID = 4;

seastar::future<> handle_connection(seastar::net::quic_accept_result accept_result) {
    std::cout << "Accepted connection!" << std::endl;
    auto conn = std::move(accept_result.connection);
    auto in = conn.input(STREAM_ID);
    auto out = conn.output(STREAM_ID);

    return seastar::do_with(std::move(conn), std::move(in), std::move(out), [] (auto& conn, auto& in, auto& out) {
        return seastar::keep_doing([&in, &out] {
            return in.read().then([&out] (seastar::temporary_buffer<char> buf) {
                const auto msg = std::string_view{ buf.begin(), buf.size() };
                std::cout << "Received message: " << msg << std::endl;
                return out.write(std::move(buf)).then([&out] {
                    return out.flush();
                });
            });
        });
    });
}

seastar::future<> service_loop(const uint16_t port, const std::string address,
        const std::string cert_file, const std::string key_file)
{
    return seastar::do_with(seastar::net::quic_listen({ seastar::net::inet_address(address), port }, cert_file, key_file),
        [] (auto& listener) {
                return seastar::keep_doing([&listener] {
                    return listener.accept().then([] (auto result) {
                        (void) handle_connection(std::move(result));
                    });
                });
            }
    );
}

int main(int ac, char** av) {
    seastar::app_template app;
    app.add_options()
            ("port", bpo::value<uint16_t>()->default_value(1234), "Server port")
            ("address", bpo::value<std::string>()->default_value("127.0.0.1"), "Server IP address")
            ("cert,c", bpo::value<std::string>()->required(), "Server certificate file")
            ("key,k", bpo::value<std::string>()->required(), "Certificate key");

    return app.run(ac, av, [&] {
        auto&& config = app.configuration();
        auto port = config["port"].as<uint16_t>();
        auto address = config["address"].as<std::string>();
        auto crt = config["cert"].as<std::string>();
        auto key = config["key"].as<std::string>();
        return service_loop(port, address, crt, key);
    });
}
