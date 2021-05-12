//
// Created by nr on 5/10/21.
//

#include "http_server.h"

#include <iomanip>
#include <iostream>
#include <sstream>

#include <cmath>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace Http {
    using namespace std::literals;

// ---------- Sha1 ------------

    Sha1::Sha1(std::string_view str) {
        SHA1((const unsigned char*)str.data(), str.size(), sha1_);
    }

    std::string Sha1::GetHexRepresentation() const {
        std::ostringstream os;
        os.fill('0');
        os << std::hex;
        for (std::size_t s = 0; s < SHA_DIGEST_LENGTH; ++s) {
            os << std::setw(2) << static_cast<unsigned int>(sha1_[s]);
        }
        return os.str();
    }

    const unsigned char* Sha1::GetPtr() const {
        return sha1_;
    }

    bool operator==(const Sha1& lhs, const Sha1& rhs) {
        return (strncmp(reinterpret_cast<const char*>(lhs.GetPtr()),
                        reinterpret_cast<const char*>(rhs.GetPtr()),
                        SHA_DIGEST_LENGTH) == 0);
    }


// ---------- Sha1Hash --------

    size_t Sha1Hash::operator()(const Sha1 &sha) const {
        //collision are inevitable, take first sizeof(size_t) bytes from hsa1
        std::size_t result;
        std::memcpy(&result, sha.GetPtr(), sizeof(std::size_t));
        return result;
    }

// ---------- Server ----------

    int ErrExit (const std::string_view hint) {
        std::cerr << hint << std::strerror(errno);
        exit(errno);
    }

    Server::Server(int listen_port)
        : listener_(ListenerInit(listen_port))
        , run_(true)
    {
        for (int i = 0; i < THREAD_COUNT; ++i) {
            workers_.emplace_back(std::thread(&Server::Worker, this));
        }
    }

    int Server::main_cycle() {
        char buff[BUFF_SIZE];
        int read_count = BUFF_SIZE;
        while(run_) {
            int client_socket = accept(listener_, nullptr, nullptr);
            if (client_socket < 0) {
                close(listener_);
                ErrExit("Accept fail: "sv);
            }
            std::fill_n(buff, read_count, 0);
            read_count = recv(client_socket, buff, BUFF_SIZE, 0);

            if (read_count > 0) {
                AddRequest(buff);
                std::string response_body = "<p>Server ok</p>\n"s;

                std::string response = "HTTP/1.1 200 OK\r\n"s
                                       "Version: HTTP/1.1\r\n"s
                                       "Content-Type: text/html; charset=utf-8\r\n"s
                                       "Content-Length: "s + std::to_string(response_body.size()) +
                                       "\r\n\r\n"s + response_body;
                int send_count = send(client_socket, response.c_str(), response.size(), 0);
                if (send_count < 0) {
                    std::cerr << "Send err: " << std::strerror(errno);
                }
            }
            close(client_socket);
        }
        Stop();
        return 0;
    }

    void Server::Stop() {
        run_ = false; //if Stop calls, but run_ is true
        cond_var.notify_all();
        for (auto& worker : workers_) {
            worker.join();
        }
        close(listener_);
    }


    int Server::ListenerInit(int port) {
        int listener = socket(AF_INET, SOCK_STREAM, 0);
        if (listener < 0) ErrExit("socket fail: "sv);

        struct sockaddr_in addr = {AF_INET, htons(port),{ htonl(INADDR_ANY) }, {} };

        int enable = 1;
        if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
            close(listener);
            ErrExit("setsockopt fail: "sv);
        }

        if (bind(listener, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(listener);
            ErrExit("bind fail: "sv);
        }

        if (listen(listener, SOMAXCONN) < 0) {
            close(listener);
            ErrExit("listen fail: "sv);
        }
        return listener;
    }

    void Server::AddRequest(std::string_view request) {
        const auto headers = detail::SplitBy(request, "\r\n"sv);
        std::string query_path;
        std::string user_agent;

        for (const auto& line : headers) {
            if (line.find("GET"sv) == 0) {
                constexpr sv_size prefix_size = 4; // 'GET '
                const sv_size end_path = line.find(' ', prefix_size);
                query_path = std::string(line.substr(prefix_size, end_path - prefix_size));
                if (query_path == "/42"s) { //for check server stop
                    run_ = false;
                }
            }
            if (line.find("User-Agent"sv) == 0) {
                constexpr sv_size prefix_size = 12; // 'User-Agent: '
                user_agent = std::string(line.substr(prefix_size));
            }
            if (!query_path.empty() && !user_agent.empty()) {
                break;
            }
        }
        {
            std::scoped_lock guard(requests_mtx_);
            requests_.emplace(std::move(query_path), std::move(user_agent));
        }
        cond_var.notify_one();
    }



    void Server::Worker() {
        const std::thread::id id = std::this_thread::get_id();
        {
            std::scoped_lock lock(output_mtx_);
            std::cout << "Start ["sv << id << "]\n"sv;
        }
        while(run_) {
            std::unique_lock<std::mutex> locker(thread_mtx_);
            cond_var.wait(locker, [this](){ return !(requests_.empty() && run_); });

            while(!requests_.empty()) {
                RequestInfo info;
                {
                    std::scoped_lock guard(requests_mtx_);
                    //another thread may get last request while this thread do something else
                    if (requests_.empty()) {
                        break;
                    }
                    info = std::move(requests_.front());
                    requests_.pop();
                }
                const Sha1 path_sha(info.path);
                const Sha1 user_agent_sha(info.user_agent);

                sha1_map* path_map = nullptr;
                {
                    std::scoped_lock guard(path_hitcounts_mtx_);
                    path_map = &path_hitcounts_[id];
                }
                sha1_map* user_agent_map = nullptr;
                {
                    std::scoped_lock guard(user_agent_hitcount_mtx_);
                    user_agent_map = &user_agent_hitcounts_[id];
                }

                const int path_hitcount = ++(*path_map)[path_sha];
                const int user_agent_hitcount = ++(*user_agent_map)[user_agent_sha];

                {
                    std::scoped_lock guard(output_mtx_);
                    std::cout << "<"sv << id << ">\t"sv
                    << "<"sv << info.path << ">\t"sv
                    << "<"sv << path_sha.GetHexRepresentation() << ">\t"sv
                    << "<"sv << path_hitcount << ">\t"sv
                    << "<"sv << info.user_agent << ">\t"sv
                    << "<"sv << user_agent_sha.GetHexRepresentation() << ">\t"sv
                    << "<"sv << user_agent_hitcount << ">\n"sv;
                }
            }
        }
        {
            std::scoped_lock lock(output_mtx_);
            std::cout << "Stoped ["sv << id << "]\n"sv;
        }
    }

// ---------- Supporting function ------------

    std::vector<std::string_view> detail::SplitBy(std::string_view request,
                                          std::string_view by) {
        std::vector<std::string_view> result;
        const std::size_t by_size = by.size();
        while(true) {
            const std::string_view::size_type by_pos = request.find(by);
            result.push_back(request.substr(0, by_pos));
            if (by_pos == std::string_view::npos) {
                break;
            }
            request.remove_prefix(by_pos + by_size);
        }
        return result;
    }
}
