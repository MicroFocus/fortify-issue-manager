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
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.IOUtils;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

final class FortifyClient
{
    enum GrantType
    {
        CLIENT_CREDENTIALS
        {
            @Override
            public void addCredentials(final FormBody.Builder builder, final String id, final String secret)
            {
                builder.add("grant_type", "client_credentials")
                    .add("client_id", id)
                    .add("client_secret", secret);
            }
        },
        PASSWORD
        {
            @Override
            public void addCredentials(final FormBody.Builder builder, final String id, final String secret)
            {
                builder.add("grant_type", "password")
                    .add("username", id)
                    .add("password", secret);
            }
        };

        public abstract void addCredentials(FormBody.Builder builder, String id, String secret);
    };

    public final static int MAX_SIZE = 50;
    private final static int CONNECTION_TIMEOUT = 30; // seconds
    private final static int WRITE_TIMEOUT = 600; // seconds
    private final static int READ_TIMEOUT = 600; // seconds

    private final String apiUrl;
    private final OkHttpClient client;
    private String token;
    private final String scope;
    private final GrantType grantType;

    private final String id;
    private final String secret;

    private final Map<String, String> proxySettings;

    /*
     * Constructor that encapsulates the connection to Fortify
     */
    FortifyClient(
        final GrantType grantType,
        final String id,
        final String secret,
        final String apiUrl,
        final String scope,
        final Map<String, String> proxySettings
    )
    {
        this.grantType = grantType;
        this.id = id;
        this.secret = secret;
        this.apiUrl = apiUrl;
        this.scope = scope;
        this.proxySettings = proxySettings;

        client = createClient();
    }

    /**
     * Used for authenticating in the case of a time out using the saved apiConnection credentials.
     *
     * @throws java.io.IOException in some circumstances
     * @throws FortifyAuthenticationException if user cannot be authenticated
     */
    public void authenticate() throws IOException, FortifyAuthenticationException
    {
        final Request request = new Request.Builder()
            .url(apiUrl + "/oauth/token")
            .post(createRequestBody())
            .build();
        final Response response = client.newCall(request).execute();

        if (!response.isSuccessful()) {
            throw new IOException("Unexpected code " + response);
        }

        final ResponseBody body = response.body();
        if (body == null) {
            throw new FortifyAuthenticationException("Unable to authenticate Fortify user. Response is null for POST /oauth/token");
        }

        // Read the results and close the response
        try (final InputStream responseStream = body.byteStream()) {
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
    private OkHttpClient createClient()
    {
        final OkHttpClient.Builder baseClient = new OkHttpClient().newBuilder()
            .connectTimeout(CONNECTION_TIMEOUT, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT, TimeUnit.SECONDS);

        if (!proxySettings.isEmpty()) {
            final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxySettings.get("host"),
                                                                                 Integer.valueOf(proxySettings.get("port"))));
            baseClient.proxy(proxy);
        }

        return baseClient.build();
    }

    private RequestBody createRequestBody()
    {
        final FormBody.Builder builder = new FormBody.Builder();
        builder.add("scope", scope);
        grantType.addCredentials(builder, id, secret);

        return builder.build();
    }

    public String getToken()
    {
        return token;
    }

    public String getApiUrl()
    {
        return apiUrl;
    }

    public OkHttpClient getClient()
    {
        return client;
    }
}
