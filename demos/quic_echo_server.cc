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
#include <seastar/core/thread.hh>
#include <seastar/core/sleep.hh>

constexpr static std::uint64_t STREAM_NUM = 100;

using namespace std::chrono_literals;

seastar::input_stream<char> arr1[STREAM_NUM];
seastar::output_stream<char> arr2[STREAM_NUM];


seastar::future<> handle_connection(seastar::net::quic_accept_result accept_result) {
    std::cout << "Accepted connection!" << std::endl;
    auto conn = std::move(accept_result.connection);
    int start = 4;
    //TODO stabilize stream numbering
    for(std::uint64_t i = 0; i < STREAM_NUM; i++){
        arr1[i] = conn.input(start);
        arr2[i] = conn.output(start);
        start += 4;
    }
    return seastar::do_with(std::move(conn), std::move(arr1), std::move(arr2), []
    (auto &conn, auto &arr1, auto &arr2) {
        return seastar::keep_doing([&arr1, &arr2]() {
            return seastar::async([&]
            {
                    auto server_read = seastar::async([&] {
                        for (std::uint64_t j = 0; j < STREAM_NUM; j++) {
                            auto buf = arr1[j].read().get();
                            char msg_buf[buf.size() + 1];
                            memcpy(msg_buf, buf.get(), buf.size());
                            msg_buf[buf.size()] = '\0';
                            std::cout << "Received message: " << msg_buf << std::endl;
                        }
                    });

                    auto server_write = seastar::async([&] {
                        for (std::uint64_t j = 0; j < STREAM_NUM; j++) {
                            seastar::sleep(2s).get();
                            std::cout << "sending message: " << j << std::endl;
                            std::string msg =
                                    "Hello from server " + std::to_string(j);
                            arr2[j].write(msg).get();
                            arr2[j].flush().get();
                        }
                    });
                    when_all(std::move(server_read), std::move(server_write)).discard_result().get();
            });
        });
    });
}

seastar::future<> service_loop() {
    // TODO: Either add keys to the repo or generate them here.
//    std::string cert_file = "/home/danielmastalerz/Pulpit/seastar_quic/quiche/quiche/examples/cert.crt";
//    std::string key_file = "/home/danielmastalerz/Pulpit/seastar_quic/quiche/quiche/examples/cert.key";
    std::string cert_file = "/home/julias/mim/zpp/seastar-master/quiche/quiche/examples/cert.crt";
    std::string key_file = "/home/julias/mim/zpp/seastar-master/quiche/quiche/examples/cert.key";

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
