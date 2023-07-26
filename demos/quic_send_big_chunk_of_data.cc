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

// Demonstration of ability to send big chunks of data. Shows the ability to buffer data, like in TCP.

#include <seastar/core/app-template.hh>
#include <seastar/core/future-util.hh>
#include <seastar/core/reactor.hh>
#include <seastar/net/api.hh>
#include <seastar/net/inet_address.hh>
#include <seastar/net/quic.hh>

namespace bpo = boost::program_options;

seastar::future<> service_loop(const uint16_t port, const std::string address) {
    constexpr static std::uint64_t STREAM_ID = 4;
    constexpr static std::uint64_t HUNDRED_MEGABYTES = 1000 * 1000 * 100;
    static char buff[HUNDRED_MEGABYTES];

    return seastar::net::quic_connect(
        { seastar::net::inet_address(address), port }
    ).then([](seastar::net::quic_connected_socket conn) {
        std::cout << "Connected!" << std::endl;
        auto out = conn.output(STREAM_ID);
        return seastar::do_with(std::move(conn), std::move(out), [] (auto& conn, auto& out) {
            return out.write(buff, HUNDRED_MEGABYTES).then([] {
                std::cout << "Able to send again!" << std::endl;
            }).then([&conn, &out] {
                // TODO Need to implement flush.
                return out.close().then([&conn] {
                    return conn.close();
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
