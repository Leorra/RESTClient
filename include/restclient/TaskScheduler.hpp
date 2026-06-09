#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace task_scheduler {

    // =========================================================
    //  TaskScheduler
    //
    //  Runs a set of periodic callbacks on a single background
    //  thread.  Each slot fires at its configured interval,
    //  measured from the moment the previous firing completed
    //  (drift-free: next_tick advances by exactly one interval,
    //  independent of callback execution time).
    //
    //  Thread-safety
    //  -------------
    //  add() / set_error_handler() -- safe to call from any thread.
    //  start() / stop()            -- must not be called concurrently
    //                                 with each other.
    //  Callbacks                   -- invoked from the worker thread.
    //
    //  Lifecycle
    //  ---------
    //  Slots survive stop()/start() cycles; only the destructor
    //  (or explicit removal, if added later) discards them.
    // =========================================================
    class TaskScheduler {
    public:
        using Callback = std::function<void()>;
        using ErrorHandler = std::function<void(std::exception_ptr)>;
        using Clock = std::chrono::steady_clock;
        using TimePoint = std::chrono::time_point<Clock>;
        using Duration = std::chrono::nanoseconds;

        explicit TaskScheduler(bool auto_start = false) {
            if (auto_start) { start(); }
        }

        ~TaskScheduler() { stop(); }

        TaskScheduler(const TaskScheduler&) = delete;
        TaskScheduler& operator=(const TaskScheduler&) = delete;
        TaskScheduler(TaskScheduler&&) = delete;
        TaskScheduler& operator=(TaskScheduler&&) = delete;

        // ---------------------------------------------------------
        //  Register a periodic callback.
        //  May be called before or after start().
        //  The first firing occurs one full interval after registration.
        // ---------------------------------------------------------
        template<typename Rep, typename Period>
        void add(std::chrono::duration<Rep, Period> interval, Callback cb) {
            const auto dur = std::chrono::duration_cast<Duration>(interval);
            if (dur.count() <= 0) {
                throw std::invalid_argument("Interval must be positive");
            }
            if (!cb) {
                throw std::invalid_argument("Callback must not be null");
            }
            {
                std::lock_guard<std::mutex> lock(slots_mtx_);
                slots_.push_back({ dur, std::move(cb), Clock::now() + dur });
            }
            cv_.notify_one();   // wake the worker so it recomputes the nearest deadline
        }

        // ---------------------------------------------------------
        //  Optional: supply a handler for exceptions thrown by callbacks.
        //  Called from the worker thread with the active exception_ptr.
        //  If not set, exceptions are silently swallowed.
        // ---------------------------------------------------------
        void set_error_handler(ErrorHandler handler) {
            std::lock_guard<std::mutex> lock(slots_mtx_);
            error_handler_ = std::move(handler);
        }

        // ---------------------------------------------------------
        //  Start the worker thread.  No-op if already running.
        // ---------------------------------------------------------
        void start() {
            if (running_.exchange(true)) { return; }
            thread_ = std::thread(&TaskScheduler::loop, this);
        }

        // ---------------------------------------------------------
        //  Stop the worker thread and wait for it to exit.
        //  Registered slots are preserved; start() may be called again.
        //  No-op if already stopped.
        // ---------------------------------------------------------
        void stop() {
            if (!running_.exchange(false)) { return; }
            cv_.notify_all();
            if (thread_.joinable()) { thread_.join(); }
            // Intentionally do NOT clear slots_ here: a subsequent
            // start() should resume firing all registered tasks.
        }

        [[nodiscard]] bool is_running() const noexcept {
            return running_.load(std::memory_order_relaxed);
        }

    private:
        struct Slot {
            Duration  interval;
            Callback  callback;
            TimePoint next_tick;
        };

        std::vector<Slot>       slots_;
        std::mutex              slots_mtx_;
        std::condition_variable cv_;
        std::thread             thread_;
        std::atomic<bool>       running_ { false };
        ErrorHandler            error_handler_;   // guarded by slots_mtx_

        // ---------------------------------------------------------
        //  Worker loop
        // ---------------------------------------------------------
        void loop() {
            while (running_.load(std::memory_order_relaxed)) {

                std::vector<Callback> due;

                {
                    std::unique_lock<std::mutex> lock(slots_mtx_);

                    if (slots_.empty()) {
                        // No slots yet -- block until one is added or we are stopped.
                        cv_.wait(lock, [this] {
                            return !running_.load(std::memory_order_relaxed)
                                || !slots_.empty();
                        });
                    } else {
                        // Compute the nearest upcoming deadline.
                        TimePoint wake_at = TimePoint::max();
                        for (const auto& s : slots_) {
                            if (s.next_tick < wake_at) { wake_at = s.next_tick; }
                        }

                        // Wait until that deadline, a stop signal, or a new slot
                        // added with an earlier deadline (notify_one in add()).
                        cv_.wait_until(lock, wake_at, [this] {
                            if (!running_.load(std::memory_order_relaxed)) { return true; }
                            const auto now = Clock::now();
                            for (const auto& s : slots_) {
                                if (now >= s.next_tick) { return true; }
                            }
                            return false;
                        });
                    }

                    if (!running_.load(std::memory_order_relaxed)) { break; }

                    const auto now = Clock::now();
                    for (auto& s : slots_) {
                        if (now >= s.next_tick) {
                            due.push_back(s.callback);
                            // Advance by exactly one interval to prevent drift.
                            // If multiple intervals have elapsed (e.g. the process
                            // was suspended), advance by as many as needed so that
                            // next_tick is always strictly in the future.
                            do {
                                s.next_tick += s.interval;
                            } while (s.next_tick <= now);
                        }
                    }
                }   // release slots_mtx_ before invoking callbacks

                // Invoke callbacks outside the lock so they may safely call add().
                for (const auto& cb : due) {
                    try {
                        cb();
                    } catch (...) {
                        ErrorHandler handler;
                        {
                            std::lock_guard<std::mutex> lock(slots_mtx_);
                            handler = error_handler_;
                        }
                        if (handler) {
                            try {
                                handler(std::current_exception());
                            } catch (...) {
                                // Error handler must not throw; if it does, ignore.
                            }
                        }
                        // Continue to next callback regardless.
                    }
                }
            }
        }
    };

} // namespace task_scheduler