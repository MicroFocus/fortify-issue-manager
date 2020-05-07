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
    public void setProxyHost(String proxyHost)
    {
        this.proxyHost = proxyHost;
    }
    public int getProxyPort()
    {
        return proxyPort;
    }
    public void setProxyPort(int proxyPort)
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

    /*
    private String titleFormat;
    private String epic;
    private String affectsVersion;
    private String fixVersion;
    private Map<String, String> teams;
    */
    /*
    public String getTitleFormat()
    {
        return titleFormat;
    }

    public void setTitleFormat(String titleFormat)
    {
        this.titleFormat = titleFormat;
    }

    public String getEpic()
    {
        return epic;
    }

    public void setEpic(String epic)
    {
        this.epic = epic;
    }

    public String getAffectsVersion()
    {
        return affectsVersion;
    }

    public void setAffectsVersion(String affectsVersion)
    {
        this.affectsVersion = affectsVersion;
    }

    public String getFixVersion()
    {
        return fixVersion;
    }

    public void setFixVersion(String fixVersion)
    {
        this.fixVersion = fixVersion;
    }

    public Map<String, String> getTeams()
    {
        return teams;
    }

    public void setTeams(Map<String, String> teams)
    {
        this.teams = teams;
    }
    */
}
