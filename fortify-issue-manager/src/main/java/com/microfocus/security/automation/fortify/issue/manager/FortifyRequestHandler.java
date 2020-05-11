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
import java.lang.reflect.Type;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
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
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

final class FortifyRequestHandler
{
    private static final Logger LOGGER = LoggerFactory.getLogger(FortifyRequestHandler.class);

    private final FortifyClient fortifyClient;
    private final Gson gson;

    public FortifyRequestHandler(final FortifyClient fortifyClient) {
        this.fortifyClient = fortifyClient;
        this.gson = new Gson();
    }

    public List<Application> getApplications(final FilterList filters, final String fields) throws IOException {
        final String content = performRequest("api/v3/applications", filters, fields);

        final Type t = new TypeToken<GenericListResponse<Application>>() {}.getType();
        final GenericListResponse<Application> results = gson.fromJson(content, t);
        if (results.getItems().size() > 0)
        {
            return results.getItems();
        }
        else
        {
            return null;
        }
    }

    public List<Release> getReleases(final FilterList filters, final String fields) throws IOException {
        final String content = performRequest("api/v3/releases", filters, fields);
        final Type t = new TypeToken<GenericListResponse<Release>>() {}.getType();
        final GenericListResponse<Release> results = gson.fromJson(content, t);
        if (results.getItems().size() > 0)
        {
            return results.getItems();
        }
        else
        {
            return null;
        }
    }

    public List<Vulnerability> getVulnerabilities(final int releaseId, final FilterList filters, final String fields)
            throws IOException {
        final String content = performRequest("api/v3/releases/" + releaseId + "/vulnerabilities", filters, fields);

        final Type t = new TypeToken<GenericListResponse<Vulnerability>>() {}.getType();
        final GenericListResponse<Vulnerability> results = gson.fromJson(content, t);
        if (results.getItems().size() > 0)
        {
            return results.getItems();
        }
        else
        {
            return null;
        }
    }

    private String performRequest(final String api, final FilterList filters, final String fields) throws IOException
    {
        HttpUrl.Builder builder = HttpUrl.parse(fortifyClient.getApiUrl()).newBuilder().addPathSegments(api);

        if(filters != null)
        {
            builder = builder.addQueryParameter("filters", filters.toString());
        }

        if (fields != null && fields.length() > 0)
        {
            builder = builder.addQueryParameter("fields", fields);
        }

        final String url = builder.build().toString();

        LOGGER.debug("Performing request GET {}", api);

        final Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer " + fortifyClient.getToken())
                .addHeader("Accept", "application/json")
                .get()
                .build();
        final Response response = fortifyClient.getClient().newCall(request).execute();

        if (response.code() == HttpStatus.SC_UNAUTHORIZED || response.code() == HttpStatus.SC_FORBIDDEN) {
            // Re-authenticate
            fortifyClient.authenticate();
        }

        // Read the results and close the response
        final String responseContent = IOUtils.toString(response.body().byteStream(), "utf-8");
        response.body().close();

        return responseContent;
    }

    public void updateVulnerability(final int releaseId, final List<String> vulnerabilityIdList, final String bugLink)
            throws IOException
    {
        final String api = "api/v3/releases/" + releaseId + "/vulnerabilities/bug-link";
        final HttpUrl.Builder builder = HttpUrl.parse(fortifyClient.getApiUrl()).newBuilder().addPathSegments(api);
        final String updateVulnerabilityUrl = builder.build().toString();

        final JsonArray vulnerabilityIds = new JsonArray();
        vulnerabilityIdList.stream().forEach(id -> vulnerabilityIds.add(id));
        final JsonObject payload = new JsonObject();
        payload.addProperty("bugLink", bugLink);
        payload.add("vulnerabilityIds", vulnerabilityIds);

        LOGGER.info("Updating vulnerabilities: POST {} with {}", updateVulnerabilityUrl, payload.toString());

        /*
        // TODO
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

        // Read the results and close the response
        final String responseContent = IOUtils.toString(response.body().byteStream(), "utf-8");
        response.body().close();

        LOGGER.info("Updated vulnerabilities with bugLink {}, response: {}", bugLink, responseContent);
        */
    }
}
