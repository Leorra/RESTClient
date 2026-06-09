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

	class TaskScheduler {
	public:
		using Callback = std::function<void()>;
		using Clock = std::chrono::steady_clock;
		using TimePoint = std::chrono::time_point<Clock>;
		using Duration = std::chrono::nanoseconds;

		explicit TaskScheduler(bool auto_start = false) {
			if (auto_start) start();
		}

		~TaskScheduler() { stop(); }

		TaskScheduler(const TaskScheduler&) = delete;
		TaskScheduler& operator=(const TaskScheduler&) = delete;

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
			cv_.notify_one();
		}

		void start() {
			if (running_.exchange(true)) return;
			thread_ = std::thread(&TaskScheduler::loop, this);
		}

		void stop() {
			if (!running_.exchange(false)) return;
			cv_.notify_all();
			if (thread_.joinable()) thread_.join();

			// Optional: clear slots
			std::lock_guard<std::mutex> lock(slots_mtx_);
			slots_.clear();
		}

		[[nodiscard]] bool is_running() const noexcept {
			return running_.load();
		}

	private:
		struct Slot {
			Duration interval;
			Callback callback;
			TimePoint next_tick;
		};

		std::vector<Slot> slots_;
		std::mutex slots_mtx_;
		std::condition_variable cv_;
		std::thread thread_;
		std::atomic<bool> running_ { false };

		void loop() {
			while (running_.load()) {
				std::vector<Callback> due;
				{
					std::unique_lock<std::mutex> lock(slots_mtx_);

					if (slots_.empty()) {
						cv_.wait(lock, [this] { return !running_.load() || !slots_.empty(); });
					} else {
						TimePoint wake_at = TimePoint::max();
						for (const auto& s : slots_) {
							if (s.next_tick < wake_at) wake_at = s.next_tick;
						}
						cv_.wait_until(lock, wake_at, [this] {
							if (!running_.load()) return true;
							const auto now = Clock::now();
							for (const auto& s : slots_) {
								if (now >= s.next_tick) return true;
							}
							return false;
						});
					}

					if (!running_.load()) break;

					const auto now = Clock::now();
					for (auto& s : slots_) {
						if (now >= s.next_tick) {
							due.push_back(s.callback);
							s.next_tick = now + s.interval;
						}
					}
				}

				// Execute callbacks outside the lock
				for (auto& cb : due) {
					if (cb) {
						try {
							cb();
						} catch (const std::exception& e) {
							// Log or ignore - don't crash the scheduler
							// Optionally add error handler callback
							(void)e; // Suppress unused variable warning)
						} catch (...) {
							// Ignore unknown exceptions
						}
					}
				}
			}
		}
	};

} // namespace task_scheduler