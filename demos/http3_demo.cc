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
 * Copyright (C) 2022 ScyllaDB Ltd.
 */

#include <seastar/http/http3.hh>
#include <seastar/http/handlers.hh>
#include <seastar/http/function_handlers.hh>
#include <seastar/core/reactor.hh>
#include <seastar/http/api_docs.hh>
#include <seastar/core/thread.hh>
#include <seastar/core/print.hh>
#include <seastar/net/inet_address.hh>

class stop_signal {
    bool _caught = false;
    seastar::condition_variable _cond;
private:
    void signaled() {
        if (_caught) {
            return;
        }
        _caught = true;
        _cond.broadcast();
    }
public:
    stop_signal() {
        seastar::engine().handle_signal(SIGINT, [this] { signaled(); });
        seastar::engine().handle_signal(SIGTERM, [this] { signaled(); });
    }
    ~stop_signal() {
        // There's no way to unregister a handler yet, so register a no-op handler instead.
        seastar::engine().handle_signal(SIGINT, [] {});
        seastar::engine().handle_signal(SIGTERM, [] {});
    }
    seastar::future<> wait() {
        return _cond.wait([this] { return _caught; });
    }
    bool stopping() const {
        return _caught;
    }
};

namespace bpo = boost::program_options;

using namespace seastar;
using namespace http3;
using namespace httpd;

class handl : public httpd::handler_base {
public:
    virtual future<std::unique_ptr<http::reply> > handle(const sstring& path,
                                                         std::unique_ptr<http::request> req, std::unique_ptr<http::reply> rep) {
        rep->_content = "<b>It's some random page<b>\n";
        rep->done("html");

        return make_ready_future<std::unique_ptr<http::reply>>(std::move(rep));
    }
};

void set_routes(routes& r) {
    handl* quic = new handl();
    r.add(operation_type::GET, url("/"), quic);
}

const std::string ms_cert_default = "/home/danmas/studia/zpp/seastar_quic/localhost.pem";
const std::string ms_key_default = "/home/danmas/studia/zpp/seastar_quic/localhost-key.pem";

int main(int ac, char** av) {
    app_template app;

    app.add_options()("port", bpo::value<uint16_t>()->default_value(3334), "HTTP Server port");
    app.add_options()("cert_file", bpo::value<std::string>()->default_value(ms_cert_default), "cert file");
    app.add_options()("cert_key", bpo::value<std::string>()->default_value(ms_key_default), "cert file");

    return app.run_deprecated(ac, av, [&] {
        return seastar::async([&] {
            stop_signal stop_signal;
            auto&& config = app.configuration();

            uint16_t port = config["port"].as<uint16_t>();
            auto server = new http3_server_control();

            sstring ms_cert = config["cert_file"].as<std::string>();
            sstring ms_key = config["cert_key"].as<std::string>();

            server->start().get();

            server->set_routes(set_routes).get();
            server->listen(port, ms_cert, ms_key).get();

            std::cout << "Seastar HTTP server listening on port " << port << std::endl;
            engine().at_exit([server] {
                return server->stop();
            });

            stop_signal.wait().get();
        });
    });
}
