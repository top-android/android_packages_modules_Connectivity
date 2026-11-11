/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "NetdUpdatable"

#include "BpfHandler.h"

#include <android-base/logging.h>
#include <android-base/result.h>

#include "NetdUpdatablePublic.h"

static android::net::BpfHandler sBpfHandler;

int libnetd_updatable_init(const char* cg2_path) {
    android::base::InitLogging(/*argv=*/nullptr);
    LOG(INFO) << __func__ << ": Initializing";

    android::base::Result<void> ret = sBpfHandler.init(cg2_path);
    if (!ret.ok()) {
        LOG(ERROR) << __func__ << ": Failed: " << ret.error().message();
        // [cannon][A17·4.14] 本机 4.14.336 没有 A17 需要的 BPF backport，
        // BPF 初始化必失败。不 abort，让 netd 跳过 BPF 继续服务：
        // BpfHandler::tagSocket 会因 mCookieTagMap 无效而安全返回 -EPERM。
        // 否则 netd 崩溃循环 → system_server 卡死 → 永远开不了机。
        LOG(WARNING) << "[cannon] BPF init failed on 4.14 (degrade, netd continues without BPF)";
        return 0;
    }
    return 0;
}

int libnetd_updatable_tagSocket(int sockFd, uint32_t tag, uid_t chargeUid, uid_t realUid) {
    return sBpfHandler.tagSocket(sockFd, tag, chargeUid, realUid);
}

int libnetd_updatable_untagSocket(int sockFd) {
    return sBpfHandler.untagSocket(sockFd);
}
