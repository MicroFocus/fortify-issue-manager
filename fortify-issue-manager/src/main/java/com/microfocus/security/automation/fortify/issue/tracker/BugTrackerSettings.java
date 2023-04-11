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

class BugTrackerSettings
{
    private final String username;
    private final String password;
    private final String apiUrl;
    private final Map<String, String> proxySettings;

    public BugTrackerSettings(
            final String username,
            final String password,
            final String apiUrl,
            final Map<String, String> proxySettings)
    {
        this.username = username;
        this.password = password;
        this.apiUrl = apiUrl;
        this.proxySettings = proxySettings;
    }

    public String getUsername()
    {
        return username;
    }

    public String getPassword()
    {
        return password;
    }

    public String getApiUrl()
    {
        return apiUrl;
    }

    public Map<String, String> getProxySettings()
    {
        return proxySettings;
    }
}
