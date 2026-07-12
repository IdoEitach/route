#pragma once

#include <condition_variable>
#include <mutex>
#include <queue>

template <typename T> class SafeQueue {
private:
  std::queue<T> queue_;
  mutable std::mutex
      mutex_; // 'mutable' allows locking inside const methods later if needed
  std::condition_variable cond_var_;

public:
  SafeQueue() = default;

  // Prevent accidental copying of the entire queue container
  SafeQueue(const SafeQueue &) = delete;
  SafeQueue &operator=(const SafeQueue &) = delete;

  void push(const T &item) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(item);
    cond_var_.notify_one();
  }

  // Overload for performance with move-semantics (rvalues)
  void push(T &&item) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(std::move(item));
    cond_var_.notify_one();
  }

  // Pop method that waits for an item to be available
  // This method will block until an item is available in the queue
  T pop() {
    std::unique_lock<std::mutex> lock(mutex_);
    cond_var_.wait(lock, [this]() { return !queue_.empty(); });

    value = std::move(queue_.front());
    return queue_.pop();
  }
};
