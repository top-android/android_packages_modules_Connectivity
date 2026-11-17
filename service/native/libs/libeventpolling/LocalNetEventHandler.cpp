/*
 * Copyright (C) 2026 The Android Open Source Project
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
#define LOG_TAG "LocalNetEventHandler"

#include "libeventpolling/LocalNetEventHandler.h"

#include <memory>
#include <unistd.h>
#include <vector>

#include <bpf/BpfRingbuf.h>
#include <bpf/BpfUtils.h>
#include <log/log.h>
#include <statslog_connectivity_sdk30.h>

#include "netd.h"

namespace android::net::eventpolling {

using bpf::BpfRingbuf;
using bpf::RingbufEventPoller;

// static
LocalNetEventHandler::LocalNetEventRingbuf *LocalNetEventHandler::GetRingbuf() {
    static LocalNetEventRingbuf *const sRingbuf =
        []() -> LocalNetEventRingbuf * {
        // [cannon][A17·4.14] BPF ringbuf 是 5.8 才进主线的，4.14 上
        // /sys/fs/bpf/netd_shared/map_netd_local_net_note_op_ringbuf 永远不存在。
        // 上游 BpfRingbuf 的构造函数在 Init() 失败时直接 abort()，而这里是在
        // system_server 的 ConnectivityService 启动路径上，一 abort 就是整个
        // system_server 崩溃循环、永远卡开机动画。
        // 降级：ringbuf 不在就不建监听，本地网络访问事件直接不统计。
        if (access(LOCAL_NET_NOTE_OP_RINGBUF_PATH, F_OK) != 0) {
            ALOGW("[cannon] %s missing (kernel 4.14, no BPF ringbuf), degrade: "
                  "local net access event reporting disabled",
                  LOCAL_NET_NOTE_OP_RINGBUF_PATH);
            return nullptr;
        }
        auto rb = std::make_unique<LocalNetEventRingbuf>(
            LOCAL_NET_NOTE_OP_RINGBUF_PATH);
        return rb.release();
    }();
    return sRingbuf;
}

// static
std::vector<uint32_t> LocalNetEventHandler::ConsumeAll() {
    LocalNetEventRingbuf *ringbuf = GetRingbuf();
    if (ringbuf == nullptr) return {};

    std::vector<uint32_t> uids_pids;
    base::Result<int> ret =
        ringbuf->ConsumeAll([&](const LocalNetNoteOp &event) {
            uids_pids.push_back(event.uid);
            uids_pids.push_back(event.pid);
        });
    if (!ret.ok()) {
        ALOGW("Failed to poll ringbuf: %s", ret.error().message().c_str());
        return {};
    }
    return uids_pids;
}

} // namespace android::net::eventpolling