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
#include <seastar/net/quic.hh>  // seastar::net::quic_config_info

// Third-party API.
#include <quiche.h>

// STD.
#include <utility>              // std::exchange


namespace seastar::net {

class quiche_configuration final {
// Local definitions.
private:
    // TODO: For the time being, store these statically to make development easier.
    constexpr static const char PROTOCOL_LIST[] = "\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9";

// Fields.
private:
    quiche_config* _config = nullptr;

// Constructors + the destructor.
public:
    quiche_configuration() = delete;
    quiche_configuration(const quiche_configuration&) = delete;
    quiche_configuration& operator=(const quiche_configuration&) = delete;

    quiche_configuration(quiche_configuration&& other) noexcept
    : _config(std::exchange(other._config, nullptr))
    {}

    quiche_configuration& operator=(quiche_configuration&& other) noexcept {
        if (this != std::addressof(other)) {
            _config = std::exchange(other._config, nullptr);
        }
        return *this;
    }

    explicit quiche_configuration(const quic_connection_config& config)
    : _config(quiche_config_new(QUICHE_PROTOCOL_VERSION))
    {
        if (!_config) {
            throw std::bad_alloc{};
        }

        // TODO check return value
        quiche_config_set_application_protos(
            _config,
            reinterpret_cast<const uint8_t*>(PROTOCOL_LIST),
            sizeof(PROTOCOL_LIST) - 1
        );

        constexpr auto convert_cc = [](quic_cc_algorithm cc) constexpr noexcept -> quiche_cc_algorithm {
            switch (cc) {
                case quic_cc_algorithm::BBR:    return QUICHE_CC_BBR;
                case quic_cc_algorithm::CUBIC:  return QUICHE_CC_CUBIC;
                case quic_cc_algorithm::RENO:   return QUICHE_CC_RENO;
            }
            return QUICHE_CC_RENO;
        };

        if (config.max_idle_timeout) {
            quiche_config_set_max_idle_timeout(_config, config.max_idle_timeout.value());
        }
        quiche_config_set_max_recv_udp_payload_size(_config, config.max_recv_udp_payload_size);
        quiche_config_set_max_send_udp_payload_size(_config, config.max_send_udp_payload_size);
        quiche_config_set_initial_max_data(_config, config.initial_max_data);
        quiche_config_set_initial_max_stream_data_bidi_local(_config, config.initial_max_stream_data_bidi_local);
        quiche_config_set_initial_max_stream_data_bidi_remote(_config, config.initial_max_stream_data_bidi_remote);
        quiche_config_set_initial_max_stream_data_uni(_config, config.initial_max_stream_data_uni);
        quiche_config_set_initial_max_streams_bidi(_config, config.initial_max_streams_bidi);
        quiche_config_set_initial_max_streams_uni(_config, config.initial_max_streams_uni);
        quiche_config_set_disable_active_migration(_config, config.disable_active_migration);
        quiche_config_set_cc_algorithm(_config, convert_cc(config.congestion_control_algorithm));
        quiche_config_set_max_stream_window(_config, config.max_stream_window);
        quiche_config_set_max_connection_window(_config, config.max_connection_window);
    }

    quiche_configuration(const std::string_view cert_filepath, const std::string_view key_filepath,
            const quic_connection_config& config)
    : quiche_configuration(config)
    {
        constexpr auto handle_quiche_err = [&](auto return_code, const auto& msg) {
            constexpr decltype(return_code) OK_CODE = 0;
            if (return_code != OK_CODE) {
                // TODO: For the time being, to make development a bit easier.
                // fmt::print(stderr, "Error while initializing the QUIC configuration: \"{}\"", msg);
                throw std::runtime_error("Could not initialize a quiche configuration.");
            }
        };

        handle_quiche_err(
            quiche_config_load_cert_chain_from_pem_file(_config, cert_filepath.data()),
            "Loading the certificate file has failed."
        );
        handle_quiche_err(
            quiche_config_load_priv_key_from_pem_file(_config, key_filepath.data()),
            "Loading the key file has failed."
        );
    }

    ~quiche_configuration() noexcept {
        if (_config) {
            quiche_config_free(std::exchange(_config, nullptr));
        }
    }

// Public methods.
public:
    quiche_config* get_underlying_config() noexcept {
        return _config;
    }
};

} // namespace seastar::net
