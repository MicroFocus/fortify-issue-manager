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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.microfocus.security.automation.fortify.issue.manager.models.Release;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.microfocus.security.automation.fortify.issue.manager.models.Application;
import com.microfocus.security.automation.fortify.issue.manager.models.Vulnerability;

import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

final class FortifyRequestHandler
{
    private static final Logger LOGGER = LoggerFactory.getLogger(FortifyRequestHandler.class);
    private static final int GET_APPLICATIONS_PAGE_SIZE = 200;
    private final int LIMIT = 50;

    private final FortifyClient fortifyClient;
    private final Gson gson;

    public FortifyRequestHandler(final FortifyClient fortifyClient)
    {
        this.fortifyClient = fortifyClient;
        this.gson = new Gson();
    }

    public List<Application> getApplications(final String[] applicationIds, final String fields)
        throws IOException, FortifyRequestException
    {
        final List<Application> applications = new ArrayList<>();
        int offset = 0;
        int pageCount;

        do {
            final String url = getUrl("ssc/api/v1/projects", null, fields, "id")
                + "&start=" + offset + "&limit=" + GET_APPLICATIONS_PAGE_SIZE;
            final String content = performRequest(url);

            final JsonObject root = gson.fromJson(content, JsonObject.class);
            if (root == null || !root.has("data")) {
                break;
            }

            final JsonArray dataArray = root.getAsJsonArray("data");
            pageCount = dataArray.size();
            if (pageCount == 0) {
                break;
            }

            for (int i = 0; i < pageCount; i++) {
                final JsonObject obj = dataArray.get(i).getAsJsonObject();
                final Application app = gson.fromJson(obj, Application.class);
                applications.add(app);
            }

            offset += pageCount;
        } while (pageCount == GET_APPLICATIONS_PAGE_SIZE);

        // It is not possible to filter applications by multiple ids in the SSC API via the `q` parameter,
        // so we filter them manually after fetching all applications.
        if (applicationIds != null && applicationIds.length > 0) {
            return applications.stream()
                .filter(app -> java.util.Arrays.stream(applicationIds)
                .anyMatch(id -> String.valueOf(app.getId()).equals(id)))
                .collect(Collectors.toList());
        }

        return applications;
    }

    public List<Release> getReleases(final int applicationId, final String[] releaseIds, final String fields)
            throws IOException, FortifyRequestException {
        final List<Release> releases = new ArrayList<>();
        int offset = 0;
        int pageCount;

        do {
            final String url = getUrl("ssc/api/v1/projects/" + applicationId + "/versions", null, fields, "id")
                + "&start=" + offset + "&limit=" + LIMIT;
            final String content = performRequest(url);

            final JsonObject root = gson.fromJson(content, JsonObject.class);
            if (root == null || !root.has("data")) {
                break;
            }

            final JsonArray dataArray = root.getAsJsonArray("data");
            pageCount = dataArray.size();
            if (pageCount == 0) {
                break;
            }

            for (int i = 0; i < pageCount; i++) {
                final JsonObject obj = dataArray.get(i).getAsJsonObject();
                final Release release = gson.fromJson(obj, Release.class);
                releases.add(release);
            }

            offset += pageCount;
        } while (pageCount == LIMIT);

        // It is not possible to filter releases by id in the SSC API via the `q` parameter,
        // so we filter them manually after fetching all releases.
        if (releaseIds != null && releaseIds.length > 0) {
            return releases.stream()
                .filter(release -> java.util.Arrays.stream(releaseIds)
                    .anyMatch(id -> String.valueOf(release.getId()).equals(id)))
                .collect(Collectors.toList());
        }

        return releases;
    }

    public List<Vulnerability> getVulnerabilities(final int releaseId, final String query, final String fields)
            throws IOException, FortifyRequestException {
        final List<Vulnerability> vulnerabilities = new ArrayList<>();
        int offset = 0;
        int pageCount;

        do {
            final String url = getUrl("ssc/api/v1/projectVersions/" + releaseId + "/issues", query, fields, "id")
                    + "&start=" + offset + "&limit=" + LIMIT + "&qm=issues";

            LOGGER.debug("Fetching vulnerabilities from offset {}...", offset);
            final String content = performRequest(url);

            final JsonObject root = gson.fromJson(content, JsonObject.class);
            if (root == null || !root.has("data")) {
                LOGGER.warn("Empty or invalid response received for URL: {}: {}", url, content);
                break;
            }

            final JsonArray dataArray = root.getAsJsonArray("data");
            pageCount = dataArray.size();
            if (pageCount == 0) {
                break;
            }

            for (int i = 0; i < pageCount; i++) {
                final JsonObject obj = dataArray.get(i).getAsJsonObject();
                final Vulnerability vulnerability = gson.fromJson(obj, Vulnerability.class);
                vulnerabilities.add(vulnerability);
            }

            offset += pageCount;
            LOGGER.debug("Collected {} vulnerabilities so far...", vulnerabilities.size());

        } while (pageCount == LIMIT);

        return vulnerabilities;
    }

    private String performRequest(final String url)
        throws IOException, FortifyRequestException
    {
        LOGGER.debug("Performing request GET {}", url);

        final Request request = new Request.Builder()
            .url(url)
            .addHeader("Authorization", fortifyClient.getAuthHeader())
            .addHeader("Accept", "application/json")
            .get()
            .build();
        final Response response = fortifyClient.getClient().newCall(request).execute();

        // Read the results and close the response
        final ResponseBody body = response.body();
        if (body == null) {
            throw new FortifyRequestException("Unable to authenticate Fortify user. Response is null for GET " + url);
        }

        // Read the result
        try (final InputStream responseStream = body.byteStream()) {
            final String responseContent = IOUtils.toString(responseStream, "utf-8");
            return responseContent;
        }
    }

    public boolean addBugLinkCommentToFortifyIssues(
            final int releaseId,
            final String bugLink,
            final List<Vulnerability> vulnerabilities)
        throws FortifyRequestException
    {
        final JsonArray issuesArray = new JsonArray();
        for (final Vulnerability vulnerability : vulnerabilities) {
            final JsonObject issueObj = new JsonObject();
            issueObj.addProperty("id", vulnerability.getId());
            issueObj.addProperty("revision", vulnerability.getRevision());
            issuesArray.add(issueObj);
        }

        final JsonObject payload = new JsonObject();
        payload.add("issues", issuesArray);
        payload.add("customTagAudit", new JsonArray());
        payload.addProperty("comment", "bugURL: " + bugLink);
        payload.addProperty("hasTagComment", false);

        final String api = "ssc/api/v1/projectVersions/" + releaseId + "/issues/action/audit";
        final HttpUrl apiUrl = HttpUrl.parse(fortifyClient.getUrl());
        if (apiUrl == null) {
            final String errorMessage = String.format(
                    "Error creating request to add bug link comment to Fortify issues. " +
                            "URL %s could not be parsed", api);

            LOGGER.error(errorMessage);
            throw new FortifyRequestException(errorMessage);
        }

        final String addBugLinkCommentUrl = apiUrl.newBuilder().addPathSegments(api).build().toString();

        LOGGER.debug("Sending request to {} to add bug link comment to Fortify issues: {}",
                addBugLinkCommentUrl, payload);

        final RequestBody requestBody = RequestBody.create(MediaType.parse("application/json"), payload.toString());

        final Request request = new Request.Builder()
            .url(addBugLinkCommentUrl)
            .addHeader("Authorization", fortifyClient.getAuthHeader())
            .addHeader("Accept", "application/json")
            .post(requestBody)
            .build();

        try {
            // Sleep 6s between POST requests
            Thread.sleep(6 * 1000);

            try (final Response response = fortifyClient.getClient().newCall(request).execute()) {

                final ResponseBody body = response.body();
                if (body == null) {
                    final String errorMessage = String.format(
                            "Error sending request to %s to add bug link comment to Fortify issues: %s. " +
                                    "Response body is null",
                            addBugLinkCommentUrl, payload);
                    LOGGER.error(errorMessage);
                    throw new FortifyRequestException(errorMessage);
                }

                try (final InputStream responseStream = body.byteStream()) {
                    final String responseContent = IOUtils.toString(responseStream, "utf-8");
                    if (!response.isSuccessful()) {
                        LOGGER.error("Updating vulnerabilities (audit) failed. POST {} with {}. Error: {}",
                                addBugLinkCommentUrl, payload.toString(), responseContent);
                        return false;
                    }
                    LOGGER.debug("Successfully sent request to {} to add bug link comment to Fortify issues: {}",
                            addBugLinkCommentUrl, payload);
                }
            }
        } catch (final IOException | InterruptedException e) {
            LOGGER.error("Error sending request to {} to add bug link comment to Fortify issues: {}",
                    addBugLinkCommentUrl, payload, e);
            return false;
        }
        return true;
    }

    private String getUrl(final String api, final String query, final String fields, final String orderBy)
        throws FortifyRequestException
    {
        final HttpUrl apiUrl = HttpUrl.parse(fortifyClient.getUrl());
        if (apiUrl == null) {
            throw new FortifyRequestException("Invalid url : " + api);
        }

        final HttpUrl.Builder builder = apiUrl.newBuilder().addPathSegments(api);
        if (StringUtils.isNotEmpty(query)) {
            builder.addQueryParameter("q", query);
        }

        if (StringUtils.isNotEmpty(fields)) {
            builder.addQueryParameter("fields", fields);
        }

        if (StringUtils.isNotEmpty(orderBy)) {
            builder.addQueryParameter("orderby", orderBy);
        }

        return builder.build().toString();
    }
}
