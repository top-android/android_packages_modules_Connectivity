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

package com.android.server.connectivity;

import static android.os.MessageQueue.OnFileDescriptorEventListener.EVENT_ERROR;
import static android.os.MessageQueue.OnFileDescriptorEventListener.EVENT_INPUT;

import static com.android.server.ConnectivityStatsLog.CORE_NETWORKING_CRITICAL_COUNTS_EVENT_OCCURRED;
import static com.android.server.ConnectivityStatsLog.CORE_NETWORKING_CRITICAL_COUNTS_EVENT_OCCURRED__EVENT_TYPE__CRITICAL_COUNTS_EVENT_TYPE_LOCAL_NETWORK_ACCESS;

import android.annotation.NonNull;
import android.app.AppOpsManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Looper;
import android.util.Log;
import android.util.SparseIntArray;

import com.android.internal.annotations.VisibleForTesting;
import com.android.server.ConnectivityStatsLog;

import java.io.FileDescriptor;
import java.util.Objects;

/**
 * LocalNetEventListener reports metrics on local net access. It uses a MessageQueue to listen
 * for events in the ebpf local net note op ring buffer and then calls into native code to consume
 * the ring buffer.
 *
 * @hide
 */
public class LocalNetEventListener {
    private static final String TAG = LocalNetEventListener.class.getSimpleName();
    // See {@link android.app.AppOpsManager#OPSTR_ACCESS_LOCAL_NETWORK}
    // TODO: make this string visible to mainline
    private static final String APP_OP = "android:access_local_network";
    private final PackageManager mPackageManager;
    private final AppOpsManager mAppOpsManager;
    private final Dependencies mDeps;
    private final FileDescriptor mRingbufFd;
    private final Looper mLooper;
    private final boolean mMetricsEnabled;
    private final boolean mNoteOpsEnabled;
    private boolean mStarted;

    public LocalNetEventListener(@NonNull Context context, @NonNull Looper looper,
            boolean metricsEnabled, boolean noteOpsEnabled) {
        this(new Dependencies(), context, looper, metricsEnabled, noteOpsEnabled);
    }

    @VisibleForTesting
    public LocalNetEventListener(@NonNull final Dependencies deps, @NonNull Context context,
            @NonNull Looper looper, boolean metricsEnabled, boolean noteOpsEnabled) {
        Objects.requireNonNull(context);
        mPackageManager = context.getPackageManager();
        mAppOpsManager = context.getSystemService(AppOpsManager.class);
        mDeps = deps;
        mLooper = looper;
        mMetricsEnabled = metricsEnabled;
        mNoteOpsEnabled = noteOpsEnabled;
        mRingbufFd = mDeps.getFileDescriptor();
    }

    public static class Dependencies {
        public FileDescriptor getFileDescriptor() {
            return nativeGetLocalNetAccessRingbufFd();
        }

        public int[] consumeEvents() {
            return nativeConsumeAllLocalNetAccessEvents();
        }

        public void writeStats(final int uid, final long eventCount) {
            ConnectivityStatsLog.write_non_chained(
                    CORE_NETWORKING_CRITICAL_COUNTS_EVENT_OCCURRED,
                    uid,
                    null,
                    CORE_NETWORKING_CRITICAL_COUNTS_EVENT_OCCURRED__EVENT_TYPE__CRITICAL_COUNTS_EVENT_TYPE_LOCAL_NETWORK_ACCESS,
                    eventCount);
        }
    }

    public void start() {
        if (mStarted) {
            return;
        }
        // [cannon][A17·4.14] 4.14 内核没有 BPF ringbuf，native 层降级返回 null。
        // 直接注册 null fd 会在 MessageQueue.addOnFileDescriptorEventListener 里 NPE，
        // 把 system_server 打崩。
        if (mRingbufFd == null) {
            Log.w(TAG, "[cannon] local net access ringbuf unavailable (kernel 4.14), "
                    + "skip event listener");
            mStarted = true;
            return;
        }
        if (mMetricsEnabled || mNoteOpsEnabled) {
            mLooper.getQueue().addOnFileDescriptorEventListener(mRingbufFd,
                    EVENT_INPUT | EVENT_ERROR, this::consumeEvents);
        }
        mStarted = true;
    }

    // When the file descriptor is readable, consume all available events.
    // Consume events using Dependencies instead of reading directly from the file descriptor,
    // because in the default case we want to use the native library to correctly handle consuming
    // the ring buffer.
    private int consumeEvents(FileDescriptor fd, int events) {
        if (!mRingbufFd.equals(fd)) {
            Log.w(TAG, "Received event for unexpected FD.");
            return 0; // Stop listening
        }

        if ((events & EVENT_ERROR) != 0) {
            Log.e(TAG, "Error event on the local net access ring buffer FD");
            return 0; // Stop listening
        }

        if ((events & EVENT_INPUT) != 0) {
            try {
                int[] uidsPids = mDeps.consumeEvents();
                if (uidsPids.length % 2 != 0) {
                    Log.e(TAG, "Received malformed UID/PID list from native layer");
                    return 0;
                }
                if (mMetricsEnabled) {
                    writeStats(uidsPids);
                }
                if (mNoteOpsEnabled) {
                    reportNoteOps(uidsPids);
                }
            } catch (Exception e) {
                Log.e(TAG, "Error consuming local net access ring buffer data", e);
            }
        }

        return EVENT_INPUT | EVENT_ERROR;
    }

    private void writeStats(int[] uidsPids) {
        SparseIntArray uidCounts = new SparseIntArray();
        for (int i = 0; i < uidsPids.length; i += 2) {
            int uid = uidsPids[i];
            int currentCount = uidCounts.get(uid, 0);
            uidCounts.put(uid, currentCount + 1);
        }

        for (int i = 0; i < uidCounts.size(); i++) {
            int uid = uidCounts.keyAt(i);
            long count = uidCounts.valueAt(i);
            mDeps.writeStats(uid, count);
        }
    }

    private void reportNoteOps(int[] uidsPids) {
        for (int i = 0; i < uidsPids.length; i += 2) {
            int uid = uidsPids[i];
            // TODO: use ActivityManagerLocal#getPackageNamesForPid
            String[] packages = mPackageManager.getPackagesForUid(uid);
            if (packages == null || packages.length == 0) {
                // No packages found for this UID
                continue;
            }
            mAppOpsManager.noteOpNoThrow(
                    APP_OP,
                    uid,
                    packages[0],
                    null,
                    null);
        }
    }

    public static native FileDescriptor nativeGetLocalNetAccessRingbufFd();

    public static native int[] nativeConsumeAllLocalNetAccessEvents();
}
