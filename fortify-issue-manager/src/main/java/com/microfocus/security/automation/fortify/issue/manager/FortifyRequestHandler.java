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

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.microfocus.security.automation.fortify.issue.manager.models.Application;
import com.microfocus.security.automation.fortify.issue.manager.models.GenericListResponse;
import com.microfocus.security.automation.fortify.issue.manager.models.Release;
import com.microfocus.security.automation.fortify.issue.manager.models.Vulnerability;

import okhttp3.HttpUrl;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

final class FortifyRequestHandler
{
    private static final Logger LOGGER = LoggerFactory.getLogger(FortifyRequestHandler.class);
    private final int LIMIT = 50;

    private final FortifyClient fortifyClient;
    private final Gson gson;

    public FortifyRequestHandler(final FortifyClient fortifyClient)
    {
        this.fortifyClient = fortifyClient;
        this.gson = new Gson();
    }

    public List<Application> getApplications(final FilterList filters, final String fields)
        throws IOException, FortifyAuthenticationException, FortifyRequestException
    {
        final String url = getUrl("api/v3/applications", filters, fields, "applicationId");
        final String content = performRequest(url);

        final Type t = new TypeToken<GenericListResponse<Application>>()
        {
        }.getType();
        final GenericListResponse<Application> results = gson.fromJson(content, t);
        if (results.getTotalCount() > 0) {
            if (results.getTotalCount() > LIMIT) {
                LOGGER.warn("Too many Applications: {}", results.getTotalCount());
            }
            return results.getItems();
        } else {
            return null;
        }
    }

    public List<Release> getReleases(final FilterList filters, final String fields)
        throws IOException, FortifyAuthenticationException, FortifyRequestException
    {
        final String url = getUrl("api/v3/releases", filters, fields, "releaseId");
        final String content = performRequest(url);
        final Type t = new TypeToken<GenericListResponse<Release>>()
        {
        }.getType();
        final GenericListResponse<Release> results = gson.fromJson(content, t);
        if (results.getTotalCount() > 0) {
            if (results.getTotalCount() > LIMIT) {
                LOGGER.warn("Too many releases: {}", results.getTotalCount());
            }
            return results.getItems();
        } else {
            return null;
        }
    }

    public List<Vulnerability> getVulnerabilities(final int releaseId, final FilterList filters, final String fields)
        throws IOException, FortifyAuthenticationException, FortifyRequestException
    {
        final String url = getUrl("api/v3/releases/" + releaseId + "/vulnerabilities", filters, fields, "id");
        final String firstPageUrl = url + "&offset=0";
        final String content = performRequest(firstPageUrl);

        final Type t = new TypeToken<GenericListResponse<Vulnerability>>()
        {
        }.getType();
        final GenericListResponse<Vulnerability> results = gson.fromJson(content, t);
        if (results.getTotalCount() == 0) {
            return null;
        }
        final List<Vulnerability> vulnerabilities = new ArrayList<>(results.getItems());
        if (results.getTotalCount() > LIMIT) {
            int offset = 0;
            final int batchesCount = results.getTotalCount() / 50;
            LOGGER.debug("Getting all {} vulnerabilities in {} batches of {} each...", results.getTotalCount(), batchesCount, LIMIT);
            for (int i = 0; i < batchesCount; i++) {
                offset = offset + LIMIT;
                final String nextPageUrl = url + "&offset=" + offset;
                LOGGER.debug("Getting vulnerabilities at offset: {}...", offset);
                final List<Vulnerability> pageOfVulnerabilities = getVulnerabilities(nextPageUrl);
                vulnerabilities.addAll(pageOfVulnerabilities);
                LOGGER.debug("Got vulnerabilities {} so far", vulnerabilities.size());
            }
        }
        return vulnerabilities;
    }

    private List<Vulnerability> getVulnerabilities(final String pageUrl)
        throws IOException, FortifyAuthenticationException, FortifyRequestException
    {
        final String content = performRequest(pageUrl);

        final Type t = new TypeToken<GenericListResponse<Vulnerability>>()
        {
        }.getType();
        final GenericListResponse<Vulnerability> results = gson.fromJson(content, t);
        return results.getItems();
    }

    private String performRequest(final String url)
        throws IOException, FortifyAuthenticationException, FortifyRequestException
    {
        LOGGER.debug("Performing request GET {}", url);

        final Request request = new Request.Builder()
            .url(url)
            .addHeader("Authorization", "Bearer " + fortifyClient.getToken())
            .addHeader("Accept", "application/json")
            .get()
            .build();
        final Response response = fortifyClient.getClient().newCall(request).execute();

        if (response.code() == HttpURLConnection.HTTP_UNAUTHORIZED || response.code() == HttpURLConnection.HTTP_FORBIDDEN) {
            // Re-authenticate
            fortifyClient.authenticate();
        }

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

    public void updateVulnerability(final int releaseId, final List<String> vulnerabilityIdList, final String bugLink)
        throws IOException, FortifyRequestException
    {
        final String api = "api/v3/releases/" + releaseId + "/vulnerabilities/bug-link";
        final HttpUrl apiUrl = HttpUrl.parse(fortifyClient.getApiUrl());
        if (apiUrl == null) {
            throw new FortifyRequestException("Invalid url : " + api);
        }
        final String updateVulnerabilityUrl = apiUrl.newBuilder().addPathSegments(api).build().toString();

        final JsonArray vulnerabilityIds = new JsonArray();
        vulnerabilityIdList.stream().forEach(id -> vulnerabilityIds.add(id));
        final JsonObject payload = new JsonObject();
        payload.addProperty("bugLink", bugLink);
        payload.add("vulnerabilityIds", vulnerabilityIds);

        LOGGER.debug("Updating vulnerabilities: POST {} with {}", updateVulnerabilityUrl, payload.toString());

        /*
        // TODO Update the Fortify issue with bug link
        final RequestBody requestBody = RequestBody.create(MediaType.parse("application/json"), payload.toString());

        final Request request = new Request.Builder()
            .url(updateVulnerabilityUrl)
            .addHeader("Authorization", "Bearer " + fortifyClient.getToken())
            .addHeader("Accept", "application/json")
            .post(requestBody)
            .build();
        final Response response = fortifyClient.getClient().newCall(request).execute();

        if (response.code() == HttpStatus.SC_UNAUTHORIZED || response.code() == HttpStatus.SC_FORBIDDEN) {
            // Re-authenticate
            fortifyClient.authenticate();
        }

        // Read the result
        final ResponseBody body = response.body();
        if (body == null) {
            throw new FortifyRequestException("Unable to update vulnerability. Response is null for POST " + api);
        }

        // Read the result
        try (final InputStream responseStream = body.byteStream()) {
            final String responseContent = IOUtils.toString(responseStream, "utf-8");
            LOGGER.info("Updated vulnerabilities with bugLink {}, response: {}", bugLink, responseContent);
        }
         */
    }

    private String getUrl(final String api, final FilterList filters, final String fields, final String orderBy)
        throws FortifyRequestException
    {
        final HttpUrl apiUrl = HttpUrl.parse(fortifyClient.getApiUrl());
        if (apiUrl == null) {
            throw new FortifyRequestException("Invalid url : " + api);
        }

        final HttpUrl.Builder builder = apiUrl.newBuilder().addPathSegments(api);
        if (filters != null) {
            builder.addQueryParameter("filters", filters.toString());
        }

        if (StringUtils.isNotEmpty(fields)) {
            builder.addQueryParameter("fields", fields);
        }

        if (StringUtils.isNotEmpty(orderBy)) {
            builder.addQueryParameter("orderBy", orderBy);
        }

        return builder.build().toString();
    }
}
