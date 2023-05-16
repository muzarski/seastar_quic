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

#pragma once

#include <seastar/http/httpd.hh>
#include <seastar/net/quic.hh>
#include <seastar/http/routes.hh>

namespace seastar {

namespace http3 {

class http3_server {
    
};
    
class http3_server_control {
private:
    httpd::http_server_control _alt_svc_server;
    http3_server _server;

private:
    static sstring generate_server_name();
public:
    http3_server_control()
    : _alt_svc_server()
    , _server() {}

    future<> start(const sstring& name = generate_server_name());
    future<> stop();
    future<> set_routes(std::function<void(httpd::routes& r)> fun);
    future<> listen(socket_address addr, const std::string& cert_file, const std::string& cert_key,
                    const net::quic_connection_config& quic_config = net::quic_connection_config());
};

} // namespace http3

} // namespace seastar

