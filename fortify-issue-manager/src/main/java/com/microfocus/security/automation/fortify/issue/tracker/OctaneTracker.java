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
package com.microfocus.security.automation.fortify.issue.tracker;

import com.google.common.net.UrlEscapers;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.microfocus.security.automation.fortify.issue.manager.BugTracker;
import com.microfocus.security.automation.fortify.issue.manager.BugTrackerException;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationException;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationManager;
import com.microfocus.security.automation.fortify.issue.manager.OctaneBugTrackerSettings;
import com.microfocus.security.automation.fortify.issue.manager.models.Vulnerability;

import java.io.IOException;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public final class OctaneTracker extends BaseTracker implements BugTracker
{
    private final TrackerClient client;
    private final JsonParser parser;
    private static String browseUrl;
    private static String defectUrl;
    private static OctaneBugTrackerSettings bugTrackerSettings;

    public OctaneTracker(final ConfigurationManager cfg) throws ConfigurationException
    {
        super(cfg);
        loadConfiguration();
        browseUrl = String.format(
                "ui/entity-navigation?p=%s/%s&entityType=work_item&id=",
                bugTrackerSettings.getSharedSpaceId(),
                bugTrackerSettings.getWorkspaceId()
        );
        defectUrl = String.format(
                "/api/shared_spaces/%s/workspaces/%s/defects",
                bugTrackerSettings.getSharedSpaceId(),
                bugTrackerSettings.getWorkspaceId()
        );
        this.client = getClient(bugTrackerSettings);
        this.parser = new JsonParser();
    }

    @Override
    public String createBug(final String payload) throws BugTrackerException
    {
        try {
            final String issue = performPostRequest(
                    client,
                    defectUrl,
                    payload
            );

            // Parse the Response
            final JsonObject response = parser.parse(issue).getAsJsonObject();
            if (response.has("data") && response.get("data").isJsonArray()) {
                final JsonArray data = response.getAsJsonArray("data");
                if (data.size() == 0) {
                    throw new BugTrackerException("Issue was not created from payload: " + payload);
                }
                final JsonObject object = data.get(0).getAsJsonObject();
                final String bugLink = object.get("id").getAsString();
                return client.getApiUrl() + browseUrl + UrlEscapers.urlPathSegmentEscaper().escape(bugLink);
            } else {
                final String errors = response.get("errors").toString();
                throw new BugTrackerException(errors);
            }
        } catch (final IOException e) {
            throw new BugTrackerException(e);
        }
    }

    @Override
    public String getIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities)
    {
        Collections.sort(vulnerabilities,
                Comparator.comparing(Vulnerability::getPrimaryLocation).thenComparing(Vulnerability::getId));
        final StringBuilder issues = new StringBuilder();
        issues.append("<table><body><tr><th>&nbsp;Issue Id&nbsp;</th><th>&nbsp;Description&nbsp;</th></tr>");
        for (final Vulnerability vulnerability : vulnerabilities) {
            issues.append("<tr>")
                    .append("<td>&nbsp;<a href=\""
                            + issueBaseUrl
                            + vulnerability.getId()
                            + "\">" + vulnerability.getId()
                            + "</a>&nbsp;</td>")
                    .append("<td>&nbsp;" + vulnerability.getPrimaryLocation());
            if (vulnerability.getLineNumber() != null) {
                issues.append(" : ")
                        .append(vulnerability.getLineNumber());
            }
            issues.append("&nbsp;</td></tr>");
        }
        issues.append("</body></table>");
        return issues.toString();
    }

    @Override
    public String getOpenSourceIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities)
    {
        vulnerabilities.sort(Comparator.comparing(Vulnerability::getPrimaryLocation));
        final StringBuilder issues = new StringBuilder();
        issues.append("<table><body><tr><th>&nbsp;Issue Id&nbsp;</th><th>&nbsp;CVE ID&nbsp;"
                + "</th><th>&nbsp;Component&nbsp;</th></tr>");
        for (final Vulnerability vulnerability : vulnerabilities) {
            issues.append("<tr>")
                    .append("<td>&nbsp;<a href=\""
                            + issueBaseUrl
                            + vulnerability.getId()
                            + "\">"
                            + vulnerability.getId()
                            + "</a>&nbsp;</td>")
                    .append("<td>&nbsp;" + vulnerability.getCheckId() + "&nbsp;</td>")
                    .append("<td>&nbsp;" + vulnerability.getPrimaryLocation());
            if (vulnerability.getLineNumber() != null) {
                issues.append(" : ")
                        .append(vulnerability.getLineNumber());
            }
            issues.append("&nbsp;</td></tr>");
        }
        issues.append("</body></table>");
        return issues.toString();
    }

    private void  loadConfiguration() throws ConfigurationException
    {
        final String workspaceId = configurationManager.getConfig("TRACKER_WORKSPACE_ID", configErrors);
        final String sharedSpaceId = configurationManager.getConfig("TRACKER_SHARED_SPACE_ID", configErrors);

        if (!configErrors.isEmpty()) {
            throw new ConfigurationException("Invalid configuration " + configErrors);
        }

        bugTrackerSettings = new OctaneBugTrackerSettings(
                bugTrackerUsername,
                bugTrackerPassword,
                bugTrackerApiUrl,
                sharedSpaceId,
                workspaceId,
                proxySettings
        );
    }
}
