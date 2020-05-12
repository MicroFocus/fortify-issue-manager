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

final class FortifySettings
{
    private String username;
    private String password;
    private String tenant;
    private String scope;
    private String apiUrl;
    private String issueUrl;
    private String[] applicationIds;

    FortifySettings()
    {
        this.username = System.getenv("FORTIFY_USERNAME");
        this.password = System.getenv("FORTIFY_PASSWORD");;
        this.tenant = System.getenv("FORTIFY_TENANT");
        this.scope = System.getenv("FORTIFY_SCOPE");
        this.apiUrl = System.getenv("FORTIFY_API_URL");
        this.issueUrl = System.getenv("FORTIFY_ISSUE_URL");
        this.applicationIds = System.getenv("FORTIFY_APPLICATION_IDS").split(",");
    }

    public String getUsername()
    {
        return username;
    }

    public String getPassword()
    {
        return password;
    }

    public String getTenant()
    {
        return tenant;
    }

    public String getScope()
    {
        return scope;
    }

    public String getApiUrl()
    {
        return apiUrl;
    }

    public String getIssueUrl()
    {
        return issueUrl;
    }

    public String[] getApplicationIds()
    {
        return applicationIds;
    }

}
