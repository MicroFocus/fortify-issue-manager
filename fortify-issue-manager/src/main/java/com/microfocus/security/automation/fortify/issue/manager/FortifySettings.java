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

final class FortifySettings
{
    private final String token;
    private final String url;
    private final Map<String, String> proxySettings;
    private final String[] applicationIds;
    private final String[] releaseIds;
    private final String issueQuery;

    FortifySettings(
        final String token,
        final String url,
        final Map<String, String> proxySettings,
        final String[] applicationIds,
        final String[] releaseIds,
        final String issueQuery
    )
    {
        super();
        this.token = token;
        this.url = url;
        this.proxySettings = proxySettings;
        this.applicationIds = applicationIds;
        this.releaseIds = releaseIds;
        this.issueQuery = issueQuery;
    }

    String getToken() {
        return token;
    }

    String getUrl()
    {
        return url;
    }

    Map<String, String> getProxySettings()
    {
        return proxySettings;
    }

    String[] getApplicationIds()
    {
        return applicationIds;
    }

    String[] getReleaseIds()
    {
        return releaseIds;
    }

    String getIssueQuery() {
        return issueQuery;
    }
}
