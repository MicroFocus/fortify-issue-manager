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

import java.util.List;

public final class BugTrackerSettings
{
    private String username;
    private String password;
    private String apiUrl;
    private String proxyHost;
    private int proxyPort;
    private List<Script> scripts;

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
    public String getApiUrl()
    {
        return apiUrl;
    }
    public void setApiUrl(final String apiUrl)
    {
        this.apiUrl = apiUrl;
    }
    public String getProxyHost()
    {
        return proxyHost;
    }
    public void setProxyHost(final String proxyHost)
    {
        this.proxyHost = proxyHost;
    }
    public int getProxyPort()
    {
        return proxyPort;
    }
    public void setProxyPort(final int proxyPort)
    {
        this.proxyPort = proxyPort;
    }
    public List<Script> getScripts()
    {
        return scripts;
    }
    public void setScripts(final List<Script> scripts)
    {
        this.scripts = scripts;
    }
}
