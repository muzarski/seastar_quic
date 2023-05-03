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
 * Copyright 2015 Cloudius Systems
 */

#include <seastar/http/httpd.hh>
#include <seastar/http/handlers.hh>
#include <seastar/http/function_handlers.hh>
#include <seastar/core/reactor.hh>
#include "demo.json.hh"
#include <seastar/http/api_docs.hh>
#include <seastar/core/thread.hh>
#include <seastar/core/print.hh>
#include <seastar/net/inet_address.hh>
#include "../lib/stop_signal.hh"

namespace bpo = boost::program_options;

using namespace seastar;
using namespace httpd;

class handl : public httpd::handler_base {
public:
    virtual future<std::unique_ptr<http::reply> > handle(const sstring& path,
            std::unique_ptr<http::request> req, std::unique_ptr<http::reply> rep) {
        rep->_content = "<b>You're using HTTP over TCP!<b>\n";
        rep->done("html");
        rep->add_header("Alt-Svc", "h3=\":3333\"");

        return make_ready_future<std::unique_ptr<http::reply>>(std::move(rep));
    }
};

void set_routes(routes& r) {
    handl* quic = new handl();
    r.add(operation_type::GET, url("/"), quic);
}

int main(int ac, char** av) {
    app_template app;

    app.add_options()("port", bpo::value<uint16_t>()->default_value(3334), "HTTP Server port");

    return app.run_deprecated(ac, av, [&] {
        return seastar::async([&] {
            seastar_apps_lib::stop_signal stop_signal;
            auto&& config = app.configuration();

            uint16_t port = config["port"].as<uint16_t>();
            auto server = new http_server_control();

            seastar::shared_ptr<seastar::tls::credentials_builder> creds = seastar::make_shared<seastar::tls::credentials_builder>();
            sstring ms_cert = "/home/daniel/Desktop/seastar_quic/cmake-build-debug/apps/httpd/localhost.pem";
            sstring ms_key = "/home/daniel/Desktop/seastar_quic/cmake-build-debug/apps/httpd/localhost-key.pem";

            creds->set_dh_level(seastar::tls::dh_params::level::MEDIUM);

            creds->set_x509_key_file(ms_cert, ms_key, seastar::tls::x509_crt_format::PEM).get();
            creds->set_system_trust().get();
            std::cout << "set keys\n";
            server->start().get();

            server->server().invoke_on_all([creds](http_server& server) {
                server.set_tls_credentials(creds->build_server_credentials());
                return make_ready_future<>();
            }).get();



            server->set_routes(set_routes).get();
            server->listen(port).get();

            std::cout << "Seastar HTTP server listening on port " << port << " ...\n";
            engine().at_exit([server] {
               return server->stop();
            });

            stop_signal.wait().get();
        });
    });
}
