/*
 * Copyright 2020-2023 Open Text.
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
package com.microfocus.security.automation.fortify.issue.tracker;

import java.util.Map;

final class OctaneBugTrackerSettings extends BugTrackerSettings
{
    private final int sharedSpaceId;
    private final int workspaceId;

    public OctaneBugTrackerSettings(
            final String username,
            final String password,
            final String apiUrl,
            final int sharedSpaceId,
            final int workspaceId,
            final Map<String, String> proxySettings)
    {
        super(username, password, apiUrl, proxySettings);
        this.sharedSpaceId = sharedSpaceId;
        this.workspaceId = workspaceId;
    }

    public int getSharedSpaceId() {
        return sharedSpaceId;
    }

    public int getWorkspaceId() {
        return workspaceId;
    }
}
