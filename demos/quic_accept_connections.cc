//
// Created by danielmastalerz on 18.01.23.
//

#include <seastar/core/app-template.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/future-util.hh>
#include <seastar/net/api.hh>
#include <seastar/net/quic.hh>

seastar::future<> service_loop() {
    // TODO: Either add keys to the repo or generate them here.
    std::string cert_file = "cert.crt";
    std::string key_file = "cert.key";

    return seastar::do_with(seastar::net::quic_listen(seastar::make_ipv4_address({1234}), cert_file, key_file),
                            [](auto &listener) {
                                return seastar::keep_doing([&listener]() {
                                    return listener.accept().then([](seastar::net::quic_accept_result result) {
                                        std::cout << "Connection accepted from " << result.remote_address << std::endl;
                                        return seastar::make_ready_future<>();
                                    });
                                });
                            });
}

int main(int ac, char **av) {
    seastar::app_template app;
    // TODO: Uncomment when compiling here will work without linking problems.
    // return app.run(ac, av, service_loop);
    return app.run(ac, av, []() { return seastar::make_ready_future(); });
}
