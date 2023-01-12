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

#include <seastar/core/iostream.hh>
#include <seastar/net/quic.hh>
#include <quiche.h>

namespace seastar::net {

    class quic_data_sink_impl : public data_sink_impl {
    public:
        temporary_buffer<char> allocate_buffer(size_t size) override {
            return temporary_buffer<char>(size);
        }
        
        future<> put(packet data) override {
            return make_ready_future<>();
        }
        
        future<> put(std::vector<temporary_buffer<char>> data) override {
            return make_ready_future<>();    
        }
        
        future<> put(temporary_buffer<char> buf) override {
            return make_ready_future<>();
        }
        
        future<> flush() override {
            return make_ready_future<>();
        }
        
        future<> close() override {
            return make_ready_future<>();
        }
        
        [[nodiscard]] size_t buffer_size() const noexcept override {
            return 0;
        }
        
    };

    class quic_data_source_impl : public data_source_impl {
    public:
        future<temporary_buffer<char>> get() override {
           return make_ready_future<temporary_buffer<char>>(); 
        }
        
        future<temporary_buffer<char>> skip(uint64_t n) override {
            return make_ready_future<temporary_buffer<char>>();
        }
        
        future<> close() override {
            return make_ready_future<>();
        }
    };

} // namespace seastar::net
