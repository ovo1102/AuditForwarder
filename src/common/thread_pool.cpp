#include "auditforwarder/thread_pool.h"

#include <utility>

namespace af {

ThreadPool::ThreadPool(std::size_t threads, std::string name)
    : name_(std::move(name)) {
    if (threads > 0) start(threads);
}

ThreadPool::~ThreadPool() { shutdown(true); }

void ThreadPool::start(std::size_t threads) {
    if (threads == 0) {
        threads = std::max<std::size_t>(2u, std::thread::hardware_concurrency());
    }
    std::lock_guard<std::mutex> lk(mtx_);
    if (!workers_.empty()) return;
    workers_.reserve(threads);
    for (std::size_t i = 0; i < threads; ++i) {
        workers_.emplace_back([this, i] { worker_loop(); (void)i; });
    }
}

void ThreadPool::shutdown(bool drain) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (stopping_.exchange(true)) return;
        if (!drain) {
            high_q_.clear();
            normal_q_.clear();
            low_q_.clear();
        }
    }
    cv_.notify_all();
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();
}

std::size_t ThreadPool::pending() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return high_q_.size() + normal_q_.size() + low_q_.size();
}

void ThreadPool::worker_loop() {
    for (;;) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lk(mtx_);
            cv_.wait(lk, [this] { return stopping_ || !high_q_.empty() || !normal_q_.empty() || !low_q_.empty(); });
            if (stopping_ && high_q_.empty() && normal_q_.empty() && low_q_.empty()) return;
            if (!high_q_.empty())            { task = std::move(high_q_.front());    high_q_.pop_front(); }
            else if (!normal_q_.empty())     { task = std::move(normal_q_.front()); normal_q_.pop_front(); }
            else                             { task = std::move(low_q_.front());    low_q_.pop_front(); }
        }
        try { task(); } catch (...) { /* swallow to keep worker alive */ }
    }
}

}  // namespace af
