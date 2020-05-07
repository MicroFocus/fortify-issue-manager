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
import com.microfocus.sepg.fortify.issue.manager.models.Application;
import com.microfocus.sepg.fortify.issue.manager.models.GenericListResponse;
import com.microfocus.sepg.fortify.issue.manager.models.Release;
import com.microfocus.sepg.fortify.issue.manager.models.Vulnerability;

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
