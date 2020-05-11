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
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.IOUtils;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

final class FortifyClient
{
    public final static int MAX_SIZE = 50;
    private final static int CONNECTION_TIMEOUT = 30; // seconds
    private final static int WRITE_TIMEOUT = 600; // seconds
    private final static int READ_TIMEOUT = 600; // seconds

    private final String apiUrl;
    private final OkHttpClient client;
    private String token;
    private final String scope;

    private final String username;
    private final String password;

    /*
     * Constructor that encapsulates the connection to Fortify
    */
    FortifyClient(final String username, final String password, final String apiUrl, final String scope) {
        this.username = username;
        this.password = password;
        this.apiUrl = apiUrl;
        this.scope = scope;

        client = createClient();
    }

    /**
     * Used for authenticating in the case of a time out using the saved apiConnection credentials.
     *
     * @throws java.io.IOException in some circumstances
     * @throws FortifyAuthenticationException if user cannot be authenticated
     */
    public void authenticate() throws IOException, FortifyAuthenticationException {

        final RequestBody formBody = new FormBody.Builder()
                    .add("scope", scope)
                    .add("grant_type", "password")
                    .add("username", username)
                    .add("password", password)
                    .build();

        final Request request = new Request.Builder()
                .url(apiUrl + "/oauth/token")
                .post(formBody)
                .build();
        final Response response = client.newCall(request).execute();

        if (!response.isSuccessful())
            throw new IOException("Unexpected code " + response);

        if(response.body() == null)
        {
            throw new FortifyAuthenticationException("Unable to authenticate Fortify user. Response is null for POST /oauth/token");
        }

        // Read the results and close the response
        try(final InputStream responseStream = response.body().byteStream()) {
            final String content = IOUtils.toString(responseStream, "utf-8");
            // Parse the Response
            final JsonParser parser = new JsonParser();
            final JsonObject obj = parser.parse(content).getAsJsonObject();
            this.token = obj.get("access_token").getAsString();
        }
    }

    /**
     * Creates a okHttp client to connect with.
     *
     * @return returns a client object
     */
    private OkHttpClient createClient() {
        final OkHttpClient.Builder baseClient = new OkHttpClient().newBuilder()
                .connectTimeout(CONNECTION_TIMEOUT, TimeUnit.SECONDS)
                .writeTimeout(WRITE_TIMEOUT, TimeUnit.SECONDS)
                .readTimeout(READ_TIMEOUT, TimeUnit.SECONDS);

        return baseClient.build();
    }

    public String getToken() {
        return token;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public OkHttpClient getClient() {
        return client;
    }
}
