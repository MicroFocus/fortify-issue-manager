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
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public final class OctaneTracker extends BaseTracker implements BugTracker {
    private static final Logger LOGGER = LoggerFactory.getLogger(OctaneTracker.class);
    private final OctaneTrackerClient client;
    private final JsonParser parser;
    private static String browseUrl;
    private static String defectUrl;
    private static OctaneBugTrackerSettings bugTrackerSettings;

    public OctaneTracker(final ConfigurationManager cfg) throws ConfigurationException {
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

        this.client = new OctaneTrackerClient(bugTrackerSettings);
        this.parser = new JsonParser();
    }

    private String performPostRequest(
        final OctaneTrackerClient client,
        final String api,
        final String payload) throws IOException, BugTrackerException {
        client.login();
        final HttpUrl apiUrl = HttpUrl.parse(client.getApiUrl());
        if (apiUrl == null) {
            throw new BugTrackerException("Invalid url : " + api);
        }
        final String url = apiUrl.newBuilder().addPathSegments(api).build().toString();
        LOGGER.debug("Performing request POST {}", url);

        final RequestBody requestBody = RequestBody.create(MediaType.parse("application/json"), payload);

        final Request request = new Request.Builder()
            .url(url)
            .post(requestBody)
            .build();

        final Response response = client.getClient().newCall(request).execute();
        if (!response.isSuccessful()) {
            throw new BugTrackerException("Failed to create issue for payload : " + payload);
        }

        // Read the result
        try (final InputStream responseStream = response.body().byteStream()) {
            final String responseContent = IOUtils.toString(responseStream, "utf-8");
            LOGGER.debug("performPostRequest response: {}", responseContent);
            return responseContent;
        }
    }

    @Override
    public String createBug(final String payload) throws BugTrackerException {
        try {
            final String issue = performPostRequest(client, defectUrl, payload);

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
    public String getIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities) {
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
    public String getOpenSourceIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities) {
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

    private void loadConfiguration() throws ConfigurationException {
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
