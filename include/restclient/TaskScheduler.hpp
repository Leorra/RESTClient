#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <functional>
#include <mutex>
#include <optional>
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
    //  add() / remove_slot() / clear_slots() /
    //  slot_count() / set_error_handler()    -- safe to call from any
    //                                            thread, including from
    //                                            within callbacks.
    //  start() / stop()                      -- safe to call from any
    //                                            thread; concurrent calls
    //                                            are serialised internally
    //                                            via lifecycle_mtx_.
    //                                            Calling stop() from within
    //                                            a callback is safe: the
    //                                            loop exits after the current
    //                                            iteration; the join is
    //                                            deferred to the next start()
    //                                            or destructor call.
    //  Callbacks                             -- invoked from the worker thread.
    //
    //  Lifecycle
    //  ---------
    //  Slots survive stop()/start() cycles; only clear_slots() or
    //  remove_slot() discards them explicitly.
    //
    //  start() rearms every slot's next_tick to "now + interval",
    //  so a slot added while stopped always fires one full interval
    //  after the scheduler is (re)started, rather than potentially
    //  firing immediately due to a stale timestamp.
    //
    //  If the worker is unable to run for an extended period
    //  (e.g. process suspension) and one or more intervals are
    //  missed, each slot fires at most once per loop iteration
    //  and its next_tick is advanced by a single interval from
    //  "now" (catch-up is capped to one tick; missed ticks are
    //  skipped rather than fired in a tight loop).
    // =========================================================
    class TaskScheduler {
    public:
        using Callback     = std::function<void()>;
        using ErrorHandler = std::function<void(std::exception_ptr)>;
        using Clock        = std::chrono::steady_clock;
        using TimePoint    = std::chrono::time_point<Clock>;
        using Duration     = std::chrono::nanoseconds;

        static constexpr Duration MIN_INTERVAL = std::chrono::nanoseconds { 1 };

        explicit TaskScheduler(bool auto_start = false, std::size_t reserve_slots = 0) {
            slots_.reserve(reserve_slots);
            if (auto_start) { start(); }
        }

        ~TaskScheduler() { stop(); }

        TaskScheduler(const TaskScheduler&)            = delete;
        TaskScheduler& operator=(const TaskScheduler&) = delete;
        TaskScheduler(TaskScheduler&&)                 = delete;
        TaskScheduler& operator=(TaskScheduler&&)      = delete;

        // ---------------------------------------------------------
        //  Register a periodic callback.
        //  Returns the index of the newly added slot (0-based).
        //  May be called before or after start(), including from
        //  within a running callback.
        //  The first firing occurs one full interval after registration
        //  (or after the next start(), if the scheduler is not running).
        //  The worker is only notified if the new slot has an earlier
        //  deadline than the current nearest, avoiding unnecessary wakeups.
        // ---------------------------------------------------------
        template<typename Rep, typename Period>
        [[nodiscard]] std::size_t add(std::chrono::duration<Rep, Period> interval,
                                      Callback cb)
        {
            const auto dur = std::chrono::duration_cast<Duration>(interval);
            if (dur < MIN_INTERVAL) {
                throw std::invalid_argument("Interval must be positive");
            }
            if (!cb) {
                throw std::invalid_argument("Callback must not be null");
            }

            bool        should_notify = false;
            std::size_t index         = 0;
            {
                std::scoped_lock lock(slots_mtx_);
                const auto deadline = Clock::now() + dur;
                should_notify = slots_.empty()
                    || deadline < nearest_deadline_unlocked();
                index = slots_.size();
                slots_.push_back({ dur, std::move(cb), deadline });
            }

            if (should_notify) { cv_.notify_one(); }
            return index;
        }

        // ---------------------------------------------------------
        //  Remove the slot at |index| (as returned by add()).
        //  Returns the removed callback, or std::nullopt if the index
        //  is out of range.
        //  Note: removal invalidates indices of all slots after |index|.
        // ---------------------------------------------------------
        [[nodiscard]] std::optional<Callback> remove_slot(std::size_t index) {
            std::scoped_lock lock(slots_mtx_);
            if (index >= slots_.size()) { return std::nullopt; }
            Callback cb = std::move(slots_[index].callback);
            slots_.erase(slots_.begin() + static_cast<std::ptrdiff_t>(index));
            cv_.notify_one();   // worker must recompute nearest deadline
            return cb;
        }

        // ---------------------------------------------------------
        //  Remove all registered slots.
        // ---------------------------------------------------------
        void clear_slots() {
            std::scoped_lock lock(slots_mtx_);
            slots_.clear();
            cv_.notify_one();
        }

        // ---------------------------------------------------------
        //  Returns the number of registered slots.
        // ---------------------------------------------------------
        [[nodiscard]] std::size_t slot_count() const {
            std::scoped_lock lock(slots_mtx_);
            return slots_.size();
        }

        // ---------------------------------------------------------
        //  Optional: supply a handler for exceptions thrown by callbacks.
        //  Called from the worker thread with the active exception_ptr.
        //  If not set, exceptions are silently swallowed.
        //  Safe to call from within a callback.
        // ---------------------------------------------------------
        void set_error_handler(ErrorHandler handler) {
            std::scoped_lock lock(slots_mtx_);
            error_handler_ = std::move(handler);
        }

        // ---------------------------------------------------------
        //  Start the worker thread.  No-op if already running.
        //  Concurrent calls are serialised by lifecycle_mtx_.
        //  Rearms every slot's next_tick to "now + interval".
        // ---------------------------------------------------------
        void start() {
            std::scoped_lock lc_lock(lifecycle_mtx_);

            if (running_.load(std::memory_order_acquire)) { return; }

            // If a previous stop()-from-callback left the thread still
            // running, wait for it to exit before spawning a new one.
            if (thread_.joinable()) { thread_.join(); }

            stop_from_worker_.store(false, std::memory_order_release);

            {
                std::scoped_lock lock(slots_mtx_);
                const auto now = Clock::now();
                for (auto& [interval, callback, next_tick] : slots_) {
                    next_tick = now + interval;
                }
            }

            running_.store(true, std::memory_order_release);
            thread_ = std::thread(&TaskScheduler::loop, this);

            // Wake the worker immediately so it picks up re-armed slots
            // rather than blocking on an outdated deadline.
            cv_.notify_one();
        }

        // ---------------------------------------------------------
        //  Stop the worker thread and wait for it to exit.
        //  Registered slots are preserved; start() may be called again.
        //  No-op if already stopped.
        //  Concurrent calls are serialised by lifecycle_mtx_.
        //
        //  Safe to call from within a callback: stop_from_worker_ is
        //  set so the loop exits after the current iteration completes.
        //  The join is deferred to the next start() or destructor call.
        // ---------------------------------------------------------
        void stop() {
            std::scoped_lock lc_lock(lifecycle_mtx_);

            if (!running_.load(std::memory_order_acquire)) { return; }

            running_.store(false, std::memory_order_release);
            cv_.notify_all();

            if (thread_.joinable()) {
                if (thread_.get_id() == std::this_thread::get_id()) {
                    // Called from within a callback: joining ourselves would
                    // deadlock.  Set the flag so the loop exits after this
                    // iteration; start() or the destructor will join.
                    stop_from_worker_.store(true, std::memory_order_release);
                } else {
                    thread_.join();
                }
            }
        }

        // ---------------------------------------------------------
        //  Returns true if the worker thread is currently running.
        // ---------------------------------------------------------
        [[nodiscard]] bool is_running() const noexcept {
            return running_.load(std::memory_order_acquire);
        }

    private:
        struct Slot {
            Duration  interval;
            Callback  callback;
            TimePoint next_tick;
        };

        // ---------------------------------------------------------
        //  Returns the nearest next_tick across all slots.
        //  Precondition: slots_mtx_ is held and slots_ is non-empty.
        // ---------------------------------------------------------
        [[nodiscard]] TimePoint nearest_deadline_unlocked() const {
            TimePoint nearest = TimePoint::max();
            for (const auto& slot : slots_) {
                if (slot.next_tick < nearest) { nearest = slot.next_tick; }
            }
            return nearest;
        }

        std::mutex              lifecycle_mtx_;          // serialises start() / stop()
        std::vector<Slot>       slots_;
        mutable std::mutex      slots_mtx_;              // guards slots_ and error_handler_
        std::condition_variable cv_;
        std::thread             thread_;
        std::atomic<bool>       running_          { false };
        std::atomic<bool>       stop_from_worker_ { false };
        ErrorHandler            error_handler_;          // guarded by slots_mtx_

        // Reused each iteration to avoid per-tick heap allocations.
        // Accessed only from the worker thread; no synchronisation needed.
        std::vector<Callback>   due_;

        // ---------------------------------------------------------
        //  Worker loop
        // ---------------------------------------------------------
        void loop() {
            while (running_.load(std::memory_order_acquire)
                && !stop_from_worker_.load(std::memory_order_acquire))
            {
                due_.clear();
                ErrorHandler handler;

                {
                    std::unique_lock<std::mutex> lock(slots_mtx_);

                    if (slots_.empty()) {
                        // No slots -- block until one is added, we are
                        // stopped, or a stop-from-worker is requested.
                        cv_.wait(lock, [this] {
                            return !running_.load(std::memory_order_acquire)
                                || stop_from_worker_.load(std::memory_order_acquire)
                                || !slots_.empty();
                        });
                    } else {
                        // Capture by value: a concurrent add() must not affect
                        // the predicate's deadline comparison mid-wait.
                        const TimePoint wake_at = nearest_deadline_unlocked();

                        cv_.wait_until(lock, wake_at, [this, wake_at] {
                            return !running_.load(std::memory_order_acquire)
                                || stop_from_worker_.load(std::memory_order_acquire)
                                || Clock::now() >= wake_at;
                        });
                    }

                    if (!running_.load(std::memory_order_acquire)
                        || stop_from_worker_.load(std::memory_order_acquire))
                    {
                        break;
                    }

                    // Snapshot the error handler once under the lock so all
                    // callbacks in this batch see a consistent handler, even
                    // if set_error_handler() is called concurrently.
                    handler = error_handler_;

                    const auto now = Clock::now();
                    for (auto& [interval, callback, next_tick] : slots_) {
                        if (now >= next_tick) {
                            // Copy: the slot must remain intact for future firings.
                            due_.push_back(callback);
                            // Advance by exactly one interval.  If multiple
                            // intervals have elapsed (e.g. process suspension),
                            // skip missed ticks to prevent a catch-up storm.
                            next_tick += interval;
                            if (next_tick <= now) { next_tick = now + interval; }
                        }
                    }
                }   // release slots_mtx_ before invoking callbacks

                // Invoke callbacks outside the lock so they may safely call
                // add(), remove_slot(), or set_error_handler() without deadlocking.
                for (const auto& cb : due_) {
                    try {
                        cb();
                    } catch (...) {
                        if (handler) {
                            try {
                                handler(std::current_exception());
                            } catch (...) {
                                // Error handler must not throw; if it does, ignore.
                            }
                        }
                        // Continue to the next callback regardless.
                    }
                }
            }
        }
    };

} // namespace task_scheduler