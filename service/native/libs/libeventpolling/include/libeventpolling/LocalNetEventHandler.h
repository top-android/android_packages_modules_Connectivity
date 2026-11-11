/**
 * Copyright (c) 2026, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <vector>

#include <android-base/unique_fd.h>
#include <bpf/RingbufEventPoller.h>

#include "netd.h"

namespace android::net::eventpolling {

// LocalNetEventHandler handles events polled from the BPF local net access
// event ring buffer.
class LocalNetEventHandler {
  public:
    LocalNetEventHandler() = delete;
    LocalNetEventHandler(const LocalNetEventHandler &) = delete;
    LocalNetEventHandler &operator=(const LocalNetEventHandler &) = delete;

    // Returns a duplicate of the ring buffer file descriptor. This is needed so
    // we can pass the file descriptor via jni for use in polling in java.
    // [cannon][A17·4.14] 内核没有 BPF ringbuf 时返回无效 fd，调用方（JNI / Java）
    // 必须容忍这种情况。
    static android::base::unique_fd GetNewRingbufFd() {
        LocalNetEventRingbuf *ringbuf = GetRingbuf();
        if (ringbuf == nullptr) return {};
        return ringbuf->GetDuplicateFd();
    }

    // Consumes all available events in the ring buffer. Returns a list of
    // alternating UIDs / PIDs, where each UID / PID pair represents a single
    // access event.
    // TODO: return a proto instead
    static std::vector<uint32_t> ConsumeAll();

  private:
    class LocalNetEventRingbuf : public bpf::BpfRingbuf<LocalNetNoteOp> {
      public:
        LocalNetEventRingbuf(const char *path)
            : BpfRingbuf<LocalNetNoteOp>(path) {}

        android::base::unique_fd GetDuplicateFd() {
            return android::base::unique_fd(
                fcntl(mRingFd.get(), F_DUPFD_CLOEXEC, 0));
        }
    };

    static LocalNetEventRingbuf *GetRingbuf();
};

} // namespace android::net::eventpolling
