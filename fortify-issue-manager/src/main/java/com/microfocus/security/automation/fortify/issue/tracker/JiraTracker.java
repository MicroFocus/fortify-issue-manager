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
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.microfocus.security.automation.fortify.issue.manager.BugTracker;
import com.microfocus.security.automation.fortify.issue.manager.BugTrackerException;
import com.microfocus.security.automation.fortify.issue.manager.BugTrackerSettings;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationException;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationManager;
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

public final class JiraTracker extends BaseTracker implements BugTracker {
    private static final Logger LOGGER = LoggerFactory.getLogger(JiraTracker.class);
    private final JiraTrackerClient client;
    private final JsonParser parser;

    public JiraTracker(final ConfigurationManager cfg) throws ConfigurationException {
        super(cfg);
        final BugTrackerSettings bugTrackerSettings = new BugTrackerSettings(
            bugTrackerUsername,
            bugTrackerPassword,
            bugTrackerApiUrl,
            proxySettings
        );
        this.client = new JiraTrackerClient(bugTrackerSettings);
        this.parser = new JsonParser();
    }

    @Override
    public String createBug(final String payload) throws BugTrackerException {
        try {
            final String issue = performPostRequest(client, "/rest/api/2/issue", payload);

            // Parse the Response
            final JsonObject response = parser.parse(issue).getAsJsonObject();
            if (response.has("key")) {
                final String bugLink = response.get("key").getAsString();
                return client.getApiUrl() + "/browse/" + UrlEscapers.urlPathSegmentEscaper().escape(bugLink);
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
        issues.append("||Issue Id||Description||");
        for (final Vulnerability vulnerability : vulnerabilities) {
            issues.append("\n|[")
                .append(vulnerability.getId())
                .append("|")
                .append(issueBaseUrl)
                .append(vulnerability.getId())
                .append("]|")
                .append(vulnerability.getPrimaryLocation());
            if (vulnerability.getLineNumber() != null) {
                issues.append(" : ")
                    .append(vulnerability.getLineNumber());
            }
            issues.append("|");
        }
        return issues.toString();
    }

    @Override
    public String getOpenSourceIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities) {
        vulnerabilities.sort(Comparator.comparing(Vulnerability::getPrimaryLocation));

        final StringBuilder issues = new StringBuilder();
        issues.append("||Issue Id||CVE ID||Component||");
        for (final Vulnerability vulnerability : vulnerabilities) {
            issues.append("\n|[")
                .append(vulnerability.getId())
                .append("|")
                .append(issueBaseUrl)
                .append(vulnerability.getId())
                .append("]|")
                .append(vulnerability.getCheckId())
                .append("|")
                .append(vulnerability.getPrimaryLocation());
            if (vulnerability.getLineNumber() != null) {
                issues.append(" : ")
                    .append(vulnerability.getLineNumber());
            }
            issues.append("|");
        }
        return issues.toString();
    }

    private String performPostRequest(
        final JiraTrackerClient client,
        final String api,
        final String payload) throws IOException, BugTrackerException {
        final HttpUrl apiUrl = HttpUrl.parse(client.getApiUrl());
        if (apiUrl == null) {
            throw new BugTrackerException("Invalid url : " + api);
        }
        final String url = apiUrl.newBuilder().addPathSegments(api).build().toString();
        LOGGER.debug("Performing request POST {}", url);

        final RequestBody requestBody = RequestBody.create(MediaType.parse("application/json"), payload);

        final Request request = new Request.Builder()
            .url(url)
            .addHeader("Authorization", "Basic " + client.getBasicAuthToken())
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
}
