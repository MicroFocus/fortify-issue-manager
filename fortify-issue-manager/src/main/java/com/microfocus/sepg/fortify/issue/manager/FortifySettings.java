/*
 * Copyright 2020 Micro Focus or one of its affiliates.
 *
 * The only warranties for products and services of Micro Focus and its
 * affiliates and licensors ("Micro Focus") are set forth in the express
 * warranty statements accompanying such products and services. Nothing
 * herein should be construed as constituting an additional warranty.
 * Micro Focus shall not be liable for technical or editorial errors or
 * omissions contained herein. The information contained herein is subject
 * to change without notice.
 *
 * Contains Confidential Information. Except as specifically indicated
 * otherwise, a valid license is required for possession, use or copying.
 * Consistent with FAR 12.211 and 12.212, Commercial Computer Software,
 * Computer Software Documentation, and Technical Data for Commercial
 * Items are licensed to the U.S. Government under vendor's standard
 * commercial license.
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
