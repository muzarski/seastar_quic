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
#pragma once

// Seastar features.
#include <seastar/core/temporary_buffer.hh> // seastar::temporary_buffer
#include <seastar/net/socket_defs.hh>       // seastar::net::socket_address
#include <seastar/net/quic.hh>              // quic_byte_type

// Third-party API.
#include <quiche.h>                     // For `QUICHE_MAX_CONN_ID_LEN`.

// STD.
#include <chrono>                       // Seed for <random>.
#include <cstring>                      // std::memset, std::memcpy, std::memcmp
#include <random>                       // Generating IDs.

namespace seastar::net {

// TODO: Remove if unnecessary.
constexpr inline size_t MAX_DATAGRAM_SIZE = 65'507;
// Provide type safety.
constexpr inline size_t MAX_QUIC_CONNECTION_ID_LENGTH = QUICHE_MAX_CONN_ID_LEN;

struct send_payload {
    temporary_buffer<quic_byte_type> buffer;
    socket_address                   dst;

    send_payload() = default;

    send_payload(temporary_buffer<quic_byte_type>&& buf, const socket_address& dest)
    : buffer(std::move(buf))
    , dst(dest)
    {}

    send_payload(temporary_buffer<quic_byte_type>&& buf, const ::sockaddr_storage& dest, ::socklen_t dest_len)
    : buffer(std::move(buf))
    {
        // TODO: Handle IPv6.
        ::sockaddr_in addr_in{};
        std::memcpy(std::addressof(addr_in), std::addressof(dest), dest_len);
        dst = addr_in;
    }
};

struct quic_connection_id {
    uint8_t cid[MAX_QUIC_CONNECTION_ID_LENGTH];

    quic_connection_id() noexcept {
        std::memset(cid, 0, MAX_QUIC_CONNECTION_ID_LENGTH);
    }

    static quic_connection_id generate() {
        static thread_local std::mt19937 mersenne(std::chrono::system_clock::now().time_since_epoch().count());

        quic_connection_id result;

        constexpr static size_t CID_LENGTH = sizeof(MAX_QUIC_CONNECTION_ID_LENGTH);
        size_t offset = 0;

        while (offset < CID_LENGTH) {
            const auto random_number = mersenne();
            std::memcpy(result.cid + offset, &random_number, std::min(sizeof(random_number), CID_LENGTH - offset));
            offset += sizeof(random_number);
        }

        return result;
    }

    bool operator==(const quic_connection_id& other) const noexcept {
        return std::memcmp(cid, other.cid, sizeof(cid)) == 0;
    }
};

} // namespace seastar::net

namespace std {

// Allowing for hashing.
template<>
struct hash<seastar::net::quic_connection_id> {
    size_t operator()(seastar::net::quic_connection_id qcid) const noexcept {
        size_t result = 0;
        for (auto it = std::begin(qcid.cid); it != std::end(qcid.cid); ++it) {
            result ^= *it + 0x9e3779b9
                    + (seastar::net::MAX_QUIC_CONNECTION_ID_LENGTH << 6)
                    + (seastar::net::MAX_QUIC_CONNECTION_ID_LENGTH >> 2);
        }
        return result;
    }
};

} // namespace std

namespace seastar::net {

class user_closed_connection_exception : public std::exception {
public:
    [[nodiscard]] const char* what() const noexcept override {
        return "User closed the connection.";
    }
};

struct connection_data {
    quiche_conn*       conn;
    quic_connection_id id;
    socket_address     pa;
};

} // namespace seastar::net
