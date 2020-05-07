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
package com.microfocus.sepg.fortify.issue.manager;

import java.util.List;

public final class FortifySettings
{
    private String username;
    private String password;
    private String tenant;
    private String scope;
    private String apiUrl;
    private String issueUrl;
    private List<Integer> applicationIds;

    public String getUsername()
    {
        return username;
    }
    public void setUsername(final String username)
    {
        this.username = username;
    }
    public String getPassword()
    {
        return password;
    }
    public void setPassword(final String password)
    {
        this.password = password;
    }
    public String getTenant()
    {
        return tenant;
    }
    public void setTenant(final String tenant)
    {
        this.tenant = tenant;
    }
    public String getScope()
    {
        return scope;
    }
    public void setScope(final String scope)
    {
        this.scope = scope;
    }
    public String getApiUrl()
    {
        return apiUrl;
    }
    public void setApiUrl(final String apiUrl)
    {
        this.apiUrl = apiUrl;
    }
    public String getIssueUrl()
    {
        return issueUrl;
    }
    public void setIssueUrl(String issueUrl)
    {
        this.issueUrl = issueUrl;
    }
    public List<Integer> getApplicationIds()
    {
        return applicationIds;
    }
    public void setApplicationIds(final List<Integer> applicationIds)
    {
        this.applicationIds = applicationIds;
    }


}
