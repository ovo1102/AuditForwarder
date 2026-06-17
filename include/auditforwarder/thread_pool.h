#pragma once
// AuditForwarder - Fixed-size thread pool with priority queues.

#include "auditforwarder/types.h"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <thread>
#include <vector>

namespace af {

class ThreadPool {
public:
    enum class Priority { Low = 0, Normal = 1, High = 2 };

    explicit ThreadPool(std::size_t threads = 0, std::string name = "af-pool");
    ~ThreadPool();

    void start(std::size_t threads);
    void shutdown(bool drain = true);

    // Submit a task and get a future. For void-returning tasks, returns std::future<void>.
    template <typename F>
    auto submit(F&& f, Priority p = Priority::Normal)
        -> std::future<typename std::invoke_result<F>::type> {
        using R = typename std::invoke_result<F>::type;
        auto task = std::make_shared<std::packaged_task<R()>>(std::forward<F>(f));
        std::future<R> fut = task->get_future();
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (stopping_) {
                task->make_ready_at_thread_exit();
                return fut;
            }
            auto wrapper = [task]() { (*task)(); };
            switch (p) {
                case Priority::High:   high_q_.emplace_back(std::move(wrapper)); break;
                case Priority::Normal: normal_q_.emplace_back(std::move(wrapper)); break;
                case Priority::Low:    low_q_.emplace_back(std::move(wrapper)); break;
            }
        }
        cv_.notify_one();
        return fut;
    }

    std::size_t thread_count() const { return workers_.size(); }
    std::size_t pending() const;
    bool        is_running() const { return !stopping_ && !workers_.empty(); }

private:
    void worker_loop();

    mutable std::mutex                 mtx_;
    std::condition_variable            cv_;
    std::vector<std::thread>           workers_;
    std::deque<std::function<void()>>  high_q_;
    std::deque<std::function<void()>>  normal_q_;
    std::deque<std::function<void()>>  low_q_;
    std::atomic<bool>                  stopping_ { false };
    std::string                        name_;
};

class ThreadPoolScope {
public:
    explicit ThreadPoolScope(std::size_t threads = 0, std::string name = "af-scope")
        : pool_(threads, std::move(name)) { pool_.start(threads); }
    ~ThreadPoolScope() { pool_.shutdown(true); }
    ThreadPool& pool() { return pool_; }
private:
    ThreadPool pool_;
};

}  // namespace af
