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


static size_t accepted_conns = 0;

std::vector<seastar::future<>> vec;

seastar::future<> handle_connection(seastar::net::quic_accept_result accept_result) {
    std::cout << "Accepted connection!" << std::endl;
    // just let quic do its stuff
    return seastar::do_with(std::move(accept_result.connection), [](auto& conn) {
        return seastar::keep_doing([&conn] () {
           return conn.h3_poll();
        });
    });

}

seastar::future<> service_loop() {
    // TODO: Either add keys to the repo or generate them here.
    std::string cert_file = "/home/daniel/Desktop/seastar_quic/cmake-build-debug/apps/httpd/localhost.pem";
    std::string key_file = "/home/daniel/Desktop/seastar_quic/cmake-build-debug/apps/httpd/localhost-key.pem";

    return seastar::do_with(seastar::net::quic_listen(seastar::make_ipv4_address({12345}), cert_file, key_file),
                            [](auto &listener) {
                                return seastar::do_until([] () { return accepted_conns >= 100; }, [&listener]() {
                                    return listener.accept().then([](seastar::net::quic_accept_result result) {
                                        accepted_conns++;
                                        vec.push_back(handle_connection(std::move(result)));
                                    });
                                }).then([&listener] () {
                                   listener.abort_accept();
                                   return seastar::when_all(vec.begin(), vec.end()).then([] (auto res) {
                                      return seastar::make_ready_future<>(); 
                                   });
                                });
                            });
}

int main(int ac, char **av) {
    seastar::app_template app;
    return app.run(ac, av, service_loop);
}
