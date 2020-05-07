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
package com.microfocus.sepg.fortify.issue.tracker;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.microfocus.sepg.fortify.issue.manager.BugTrackerSettings;

import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public final class JiraRequestHandler
{
    private static final Logger LOGGER = LoggerFactory.getLogger(JiraRequestHandler.class);

    private final JiraClient client;
    final JsonParser parser;

    public JiraRequestHandler(final BugTrackerSettings bugTrackerSettings)
    {
        this.client = new JiraClient(
                                        bugTrackerSettings.getUsername(),
                                        bugTrackerSettings.getPassword(),
                                        bugTrackerSettings.getApiUrl(),
                                        bugTrackerSettings.getProxyHost(),
                                        bugTrackerSettings.getProxyPort()
                                    );
        this.parser = new JsonParser();
    }

    public String createBug(final String payload) throws BugTrackerException
    {
        try
        {
            final String issue = performPostRequest("rest/api/2/issue", payload);

            // Parse the Response
            final JsonObject response = parser.parse(issue).getAsJsonObject();
            if(response.has("key"))
            {
                final String bugLink = response.get("key").getAsString();
                return client.getApiUrl() + "/" + bugLink;
            }
            else
            {
                final String errors = response.get("errors").toString();
                throw new BugTrackerException(errors);
            }
        } catch (final IOException e)
        {
            throw new BugTrackerException(e);
        }
    }

    private String performPostRequest(final String api, final String payload) throws IOException
    {
        final HttpUrl.Builder builder = HttpUrl.parse(client.getApiUrl()).newBuilder().addPathSegments(api);
        final String url = builder.build().toString();
        LOGGER.info("Performing request POST {}", url);

        final RequestBody requestBody = RequestBody.create(MediaType.parse("application/json"), payload);

        final Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Basic " + client.getBasicAuthToken())
                .post(requestBody)
                .build();

        final Response response = client.getClient().newCall(request).execute();

        // Read the results and close the response
        final String responseContent = IOUtils.toString(response.body().byteStream(), "utf-8");
        response.body().close();
        LOGGER.info("performPostRequest response: {}", responseContent);
        return responseContent;
    }
}
