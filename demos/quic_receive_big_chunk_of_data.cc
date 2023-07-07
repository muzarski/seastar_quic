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
#include <seastar/core/future-util.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/net/api.hh>
#include <seastar/net/inet_address.hh>
#include <seastar/net/quic.hh>

namespace bpo = boost::program_options;

constexpr static uint64_t STREAM_ID = 4;
constexpr static size_t MAX_ACCEPTED_CONNECTIONS = 3;

seastar::future<> handle_connection(seastar::net::quic_accept_result accept_result) {
    static size_t rcv_bytes = 0;

    std::cout << "Accepted connection!" << std::endl;
    auto conn = std::move(accept_result.connection);
    auto in = conn.input(STREAM_ID);

    return seastar::do_with(std::move(conn), std::move(in), [] (auto& conn, auto& in) {
         return seastar::do_until([&in] { return in.eof(); }, [&in] {
            return in.read().then([](seastar::temporary_buffer<char> buf) {
                if (buf.empty()) {
                    return seastar::make_ready_future<>();
                }

                rcv_bytes += buf.size();
                std::cout << "Received " << buf.size() << " bytes, total " << rcv_bytes << "b" << std::endl;
                return seastar::make_ready_future();
            });
        }).then([] {
           std::cout << "Connection processed!" << std::endl;
        });
    });
}

seastar::future<> service_loop(const uint16_t port, const std::string address,
        const std::string cert_file, const std::string key_file)
{
    static size_t accepted_connections = 0;
    static std::vector<seastar::future<>> vec;

    return seastar::do_with(seastar::net::quic_listen({ seastar::net::inet_address(address), port }, cert_file, key_file),
        [] (auto& listener) {
            return seastar::do_until([] { return accepted_connections >= MAX_ACCEPTED_CONNECTIONS; }, [&listener] {
                return listener.accept().then([] (auto result) {
                    ++accepted_connections;
                    vec.push_back(handle_connection(std::move(result)));
                });
            }).then([&listener] {
                listener.abort_accept();
                return seastar::when_all(vec.begin(), vec.end()).then([] (auto result) {
                    return seastar::make_ready_future<>();
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
