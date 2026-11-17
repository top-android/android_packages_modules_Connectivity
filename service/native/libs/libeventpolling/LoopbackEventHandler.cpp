/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define LOG_TAG "LoopbackEventHandler"

#include "libeventpolling/LoopbackEventHandler.h"

#include <memory>

#include <bpf/BpfRingbuf.h>
#include <bpf/BpfUtils.h>
#include <log/log.h>
#include <statslog_connectivity_sdk30.h>

#include "netd.h"

namespace android::net::eventpolling {
namespace {

using bpf::BpfRingbuf;
using bpf::RingbufEventPoller;

uint32_t convertLoopbackResult(uint32_t result) {
    switch (result) {
    case LoopbackAccessResult::LOOPBACK_ACCESS_ALLOWED:
        return android::connectivity::stats::
            LOOPBACK_USAGE_REPORTED__RESULT__LOOPBACK_ACCESS_RESULT_ALLOWED;
    case LoopbackAccessResult::LOOPBACK_ACCESS_BLOCKED:
        return android::connectivity::stats::
            LOOPBACK_USAGE_REPORTED__RESULT__LOOPBACK_ACCESS_RESULT_BLOCKED;
    default:
        return android::connectivity::stats::
            LOOPBACK_USAGE_REPORTED__RESULT__LOOPBACK_ACCESS_RESULT_UNSPECIFIED;
    }
}

} // namespace

// static
bpf::RingbufEventPoller<LoopbackAccessEvent> *
LoopbackEventHandler::GetPoller() {
    static bpf::RingbufEventPoller<LoopbackAccessEvent> *const sPoller =
        []() -> bpf::RingbufEventPoller<LoopbackAccessEvent> * {
        // [cannon][A17·4.14] BPF ringbuf 是 5.8 才进主线的，4.14 上
        // /sys/fs/bpf/netd_shared/map_netd_loopback_access_ringbuf 不存在。
        // 上游 BpfRingbuf 的构造函数在 Init() 失败时 abort()，会把 system_server
        // 打成崩溃循环。这里改用 Create()，失败就降级为不统计 loopback 使用情况。
        auto rb = BpfRingbuf<LoopbackAccessEvent>::Create(
            LOOPBACK_ACCESS_RINGBUF_NETD_PATH);
        if (!rb.ok()) {
            ALOGW("[cannon] %s unavailable (kernel 4.14, no BPF ringbuf), degrade: "
                  "loopback usage reporting disabled: %s",
                  LOOPBACK_ACCESS_RINGBUF_NETD_PATH,
                  rb.error().message().c_str());
            return nullptr;
        }

        auto callback = [](const std::vector<LoopbackAccessEvent> &events) {
            for (const LoopbackAccessEvent &event : events) {
                android::connectivity::stats::stats_write(
                    android::connectivity::stats::LOOPBACK_USAGE_REPORTED,
                    event.src_uid, event.dst_uid,
                    convertLoopbackResult(event.result));
            }
        };

        auto result = RingbufEventPoller<LoopbackAccessEvent>::Create(
            std::move(callback), std::move(rb.value()));

        if (!result.ok()) {
            ALOGE("Failed to create RingbufEventPoller: %s",
                  result.error().message().c_str());
            return nullptr;
        }
        return result.value().release();
    }();
    return sPoller;
}

// static
bool LoopbackEventHandler::Start() {
    bpf::RingbufEventPoller<LoopbackAccessEvent> *poller = GetPoller();
    if (!poller) {
        ALOGE("LoopbackEventHandler failed to get poller instance for Start.");
        return false;
    }
    return poller->Start();
}

// static
void LoopbackEventHandler::Stop() {
    bpf::RingbufEventPoller<LoopbackAccessEvent> *poller = GetPoller();
    if (poller) {
        poller->Stop();
    } else {
        ALOGW(
            "LoopbackEventHandler::Stop() called when poller not initialized.");
    }
}

} // namespace android::net::eventpolling
