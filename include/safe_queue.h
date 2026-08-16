#pragma once

#include <condition_variable>
#include <mutex>
#include <queue>
#include <stdexcept>

enum class Pritority : size_t { High = 0, Medium = 1, Low = 2, Count = 3 };

template <typename T> class SafeQueue {
private:
  std::array<std::queue<T>, static_cast<std::size_t>(Pritority::Count)> queues_;
  mutable std::mutex
      mutex_; // 'mutable' allows locking inside const methods later if needed
  std::condition_variable cond_var_;

public:
  SafeQueue() = default;

  // Prevent accidental copying
  SafeQueue(const SafeQueue &) = delete;
  SafeQueue &operator=(const SafeQueue &) = delete;

  void push(const T &item, Pritority priority = Pritority::Low) {
    std::lock_guard<std::mutex> lock(mutex_);
    queues_[static_cast<size_t>(priority)].push(item);
    cond_var_.notify_one();
  }

  // Overload for performance with move-semantics (rvalues)
  void push(T &&item, Pritority priority = Pritority::Low) {
    std::lock_guard<std::mutex> lock(mutex_);
    queues_[static_cast<size_t>(priority)].push(std::move(item));
    cond_var_.notify_one();
  }

  // Pop method that waits for an item to be available
  // This method will block until an item is available in the queue
  T pop() {
    std::unique_lock<std::mutex> lock(mutex_);

    cond_var_.wait(lock, [this] {
      for (const auto &queue : queues_) {
        if (!queue.empty()) {
          return true;
        }
      }
      return false;
    });

    for (auto &queue : queues_) {
      if (!queue.empty()) {
        T item = std::move(queue.front());
        queue.pop();
        return item;
      }
    }
    throw std::runtime_error("SafeQueue: Unexpected empty queue state");
  }
};
