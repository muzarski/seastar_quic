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
#include <seastar/core/reactor.hh>
#include <seastar/core/future-util.hh>
#include <seastar/net/api.hh>
#include <seastar/net/quic.hh>
#include <seastar/core/sleep.hh>

constexpr static std::uint64_t STREAM_ID = 4;

seastar::future<> handle_connection(seastar::net::quic_accept_result accept_result) {
    std::cout << "Accepted connection!" << std::endl;
    auto conn = std::move(accept_result.connection);
    auto in = conn.input(STREAM_ID);
    auto out = conn.output(STREAM_ID);
    return seastar::do_with(std::move(conn), std::move(in), std::move(out), [](auto &conn, auto &in, auto &out) {
        return seastar::keep_doing([&in, &out]() {
            return in.read().then([&out](seastar::temporary_buffer<char> buf) {
                char msg_buf[buf.size() + 1];
                memcpy(msg_buf, buf.get(), buf.size());
                msg_buf[buf.size()] = '\0';
                std::cout << "Received message: " << msg_buf << std::endl;
                return out.write(std::move(buf)).then([&out]() {
                    return out.flush();
                });
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
