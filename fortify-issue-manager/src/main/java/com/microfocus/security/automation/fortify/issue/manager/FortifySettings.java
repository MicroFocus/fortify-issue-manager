/*
 * Copyright 2020 Micro Focus or one of its affiliates.
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

import com.microfocus.security.automation.fortify.issue.manager.FortifyClient.GrantType;

final class FortifySettings
{
    private final GrantType grantType;
    private final String id;
    private final String secret;
    private final String scope;
    private final String apiUrl;
    private final String issueUrl;
    private final Map<String, String> proxySettings;
    private final String[] applicationIds;
    private final String releaseFilters;
    private final String issueFilters;

    FortifySettings(
        final GrantType grantType,
        final String id,
        final String secret,
        final String scope,
        final String apiUrl,
        final String issueUrl,
        final Map<String, String> proxySettings,
        final String[] applicationIds,
        final String releaseFilters,
        final String issueFilters
    )
    {
        super();
        this.grantType = grantType;
        this.id = id;
        this.secret = secret;
        this.scope = scope;
        this.apiUrl = apiUrl;
        this.issueUrl = issueUrl;
        this.proxySettings = proxySettings;
        this.applicationIds = applicationIds;
        this.releaseFilters = releaseFilters;
        this.issueFilters = issueFilters;
    }

    GrantType getGrantType()
    {
        return grantType;
    }

    String getId()
    {
        return id;
    }

    String getSecret()
    {
        return secret;
    }

    String getScope()
    {
        return scope;
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

    String getReleaseFilters() {
        return releaseFilters;
    }

    String getIssueFilters() {
        return issueFilters;
    }
}
