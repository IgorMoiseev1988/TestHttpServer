//
// Created by nr on 5/10/21.
//
#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <cstring>

#include <openssl/sha.h>

namespace Http {

    constexpr int THREAD_COUNT = 5;
    constexpr int BUFF_SIZE = 4096;

    class Sha1 {
    public:
        explicit Sha1(std::string_view str);
        std::string GetHexRepresentation() const;
        const unsigned char* GetPtr() const;
    private:
        unsigned char sha1_[SHA_DIGEST_LENGTH];
    };

    bool operator==(const Sha1& lhs, const Sha1& rhs);

    struct Sha1Hash {
        size_t operator()(const Sha1& sha) const;
    };

    struct RequestInfo {
        RequestInfo() = default;
        RequestInfo(std::string&& path, std::string&& user_agent)
            : path(std::move(path))
            , user_agent(std::move(user_agent))
        {}
        std::string path;
        std::string user_agent;
    };

    int ErrExit (const std::string_view hint);

    class Server {
        using sv_size = std::string_view::size_type;
    public:
        explicit Server(int listen_port);
        int main_cycle();
        void Stop();
    private:
        int listener_;

        static int ListenerInit(int listen_port);
        void AddRequest(std::string_view);
        void Worker();

        std::vector<std::thread> workers_;
        std::mutex requests_mtx_, output_mtx_, thread_mtx_;
        std::queue<RequestInfo> requests_;
        std::condition_variable cond_var;
        std::atomic_bool run_;

        using sha1_map = std::unordered_map<Sha1, int, Sha1Hash>;

        std::mutex path_hitcounts_mtx_;
        std::unordered_map<std::thread::id, sha1_map> path_hitcounts_;
        std::mutex user_agent_hitcount_mtx_;
        std::unordered_map<std::thread::id, sha1_map> user_agent_hitcounts_;
    };

    namespace detail {
        std::vector<std::string_view> SplitBy(std::string_view request,
                                                     std::string_view by);
    }

}
