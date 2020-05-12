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

final class FortifyRequestHandler
{
    private static final Logger LOGGER = LoggerFactory.getLogger(FortifyRequestHandler.class);
    private final int LIMIT = 50;

    private final FortifyClient fortifyClient;
    private final Gson gson;

    public FortifyRequestHandler(final FortifyClient fortifyClient) {
        this.fortifyClient = fortifyClient;
        this.gson = new Gson();
    }

    public List<Application> getApplications(final FilterList filters, final String fields)
            throws IOException, FortifyAuthenticationException, FortifyRequestException {
        int offset = 0;
        final String content = performRequest("api/v3/applications", filters, fields, "applicationId", offset);

        final Type t = new TypeToken<GenericListResponse<Application>>() {}.getType();
        final GenericListResponse<Application> results = gson.fromJson(content, t);
        if (results.getTotalCount() > 0)
        {
            final List<Application> applications = new ArrayList<>();
            applications.addAll(results.getItems());
            if(results.getTotalCount() > LIMIT)
            {
                LOGGER.info("!!!!!!!!! GET NEXT PAGE OF APPLICATIONS...: {}", results.getTotalCount());
                offset = offset + LIMIT;
            }
            return results.getItems();
        }
        else
        {
            return null;
        }
    }

    public List<Release> getReleases(final FilterList filters, final String fields)
            throws IOException, FortifyAuthenticationException, FortifyRequestException {
        int offset = 0;
        final String content = performRequest("api/v3/releases", filters, fields, "releaseId", offset);
        final Type t = new TypeToken<GenericListResponse<Release>>() {}.getType();
        final GenericListResponse<Release> results = gson.fromJson(content, t);
        if (results.getTotalCount() > 0)
        {
            final List<Release> releases = new ArrayList<>();
            releases.addAll(results.getItems());
            if(results.getTotalCount() > LIMIT)
            {
                LOGGER.info("!!!!!!!!! GET NEXT PAGE OF RELEASES...: {}", results.getTotalCount());
                offset = offset + LIMIT;
            }
            return results.getItems();
        }
        else
        {
            return null;
        }
    }

    public List<Vulnerability> getAllVulnerabilities(final int releaseId, final FilterList filters, final String fields)
            throws IOException, FortifyAuthenticationException, FortifyRequestException {
        final String content = performRequest("api/v3/releases/" + releaseId + "/vulnerabilities", filters, fields, "id", 0);

        final Type t = new TypeToken<GenericListResponse<Vulnerability>>() {}.getType();
        final GenericListResponse<Vulnerability> results = gson.fromJson(content, t);
        if (results.getTotalCount() == 0)
        {
            return null;
        }
        final List<Vulnerability> vulnerabilities = new ArrayList<>(results.getItems());
        if(results.getTotalCount() > LIMIT)
        {
            int offset = 0;
            final int batchesCount = results.getTotalCount() / 50;
            LOGGER.info("Getting all {} vulnerabilities in {} batches of {} each...", results.getTotalCount(), batchesCount, LIMIT);
            for(int i = 0; i < batchesCount; i++)
            {
                offset = offset + LIMIT;
                LOGGER.info("Getting vulnerabilities at offset: {} with {} and {}...", offset, filters, fields);
                final List<Vulnerability> pageOfVulnerabilities = getVulnerabilities(releaseId, filters, fields, offset);
                vulnerabilities.addAll(pageOfVulnerabilities);
                LOGGER.info("Got vulnerabilities {} so far", vulnerabilities.size());
            }
        }
        return vulnerabilities;
    }

    public List<Vulnerability> getVulnerabilities(final int releaseId, final FilterList filters, final String fields, int offset)
            throws IOException, FortifyAuthenticationException, FortifyRequestException
    {
        final String content = performRequest("api/v3/releases/" + releaseId + "/vulnerabilities", filters, fields, "id", offset);

        final Type t = new TypeToken<GenericListResponse<Vulnerability>>() {}.getType();
        final GenericListResponse<Vulnerability> results = gson.fromJson(content, t);
        LOGGER.info("Got {} vulnerabilities at offset {}.", results.getItems().size(), offset);
        return results.getItems();
    }

    private String performRequest(final String api, final FilterList filters, final String fields,
            final String orderBy, final int offset)
            throws IOException, FortifyAuthenticationException, FortifyRequestException
    {
        HttpUrl.Builder builder = HttpUrl.parse(fortifyClient.getApiUrl()).newBuilder().addPathSegments(api);
        if(builder == null)
        {
            throw new FortifyRequestException("Invalid url : " + api);
        }
        if(filters != null)
        {
            builder = builder.addQueryParameter("filters", filters.toString());
        }

        if (StringUtils.isNotEmpty(fields))
        {
            builder = builder.addQueryParameter("fields", fields);
        }

        if(StringUtils.isNotEmpty(orderBy))
        {
            builder = builder.addQueryParameter("orderBy", orderBy);
        }

        builder = builder.addQueryParameter("offset", Integer.toString(offset));

        final String url = builder.build().toString();

        LOGGER.info("Performing request GET {}", url);

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
        if(response.body() == null)
        {
            throw new FortifyRequestException("Unable to authenticate Fortify user. Response is null for GET " + url);
        }

        // Read the result
        try(final InputStream responseStream = response.body().byteStream()) {
            final String responseContent = IOUtils.toString(responseStream, "utf-8");
            return responseContent;
        }
    }

    public void updateVulnerability(final int releaseId, final List<String> vulnerabilityIdList, final String bugLink)
            throws IOException, FortifyRequestException
    {
        final String api = "api/v3/releases/" + releaseId + "/vulnerabilities/bug-link";
        final HttpUrl.Builder builder = HttpUrl.parse(fortifyClient.getApiUrl()).newBuilder().addPathSegments(api);
        if(builder == null)
        {
            throw new FortifyRequestException("Invalid url : " + api);
        }
        final String updateVulnerabilityUrl = builder.build().toString();

        final JsonArray vulnerabilityIds = new JsonArray();
        vulnerabilityIdList.stream().forEach(id -> vulnerabilityIds.add(id));
        final JsonObject payload = new JsonObject();
        payload.addProperty("bugLink", bugLink);
        payload.add("vulnerabilityIds", vulnerabilityIds);

        LOGGER.info("Updating vulnerabilities: POST {} with {}", updateVulnerabilityUrl, payload.toString());

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
        if(response.body() == null)
        {
            throw new FortifyRequestException("Unable to update vulnerability. Response is null for POST " + api);
        }

        // Read the result
        try(final InputStream responseStream = response.body().byteStream()) {
            final String responseContent = IOUtils.toString(responseStream, "utf-8");
            LOGGER.info("Updated vulnerabilities with bugLink {}, response: {}", bugLink, responseContent);
        }
        */
    }
}
