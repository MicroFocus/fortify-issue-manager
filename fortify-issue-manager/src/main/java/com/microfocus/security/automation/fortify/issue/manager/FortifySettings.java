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
package com.microfocus.security.automation.fortify.issue.manager;

import java.util.Map;

import com.microfocus.security.automation.fortify.issue.manager.FortifyClient.AuthType;

final class FortifySettings
{
    private final AuthType authType;
    private final String username;
    private final String password;
    private final String token;
    private final String apiUrl;
    private final String issueUrl;
    private final Map<String, String> proxySettings;
    private final String[] applicationIds;
    private final String issueQuery;

    FortifySettings(
        final AuthType authType,
        final String username,
        final String password,
        final String token,
        final String apiUrl,
        final String issueUrl,
        final Map<String, String> proxySettings,
        final String[] applicationIds,
        final String issueQuery
    )
    {
        super();
        this.authType = authType;
        this.username = username;
        this.password = password;
        this.token = token;
        this.apiUrl = apiUrl;
        this.issueUrl = issueUrl;
        this.proxySettings = proxySettings;
        this.applicationIds = applicationIds;
        this.issueQuery = issueQuery;
    }

    AuthType getAuthType() {
        return authType;
    }

    String getUsername() {
        return username;
    }

    String getPassword() {
        return password;
    }

    String getToken() {
        return token;
    }

    String getApiUrl()
    {
        return apiUrl;
    }

    String getIssueUrl()
    {
        return issueUrl;
    }

    Map<String, String> getProxySettings()
    {
        return proxySettings;
    }

    String[] getApplicationIds()
    {
        return applicationIds;
    }

    String getIssueQuery() {
        return issueQuery;
    }
}
