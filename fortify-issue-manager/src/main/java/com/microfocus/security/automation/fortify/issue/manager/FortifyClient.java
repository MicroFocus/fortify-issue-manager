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

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import okhttp3.OkHttpClient;

final class FortifyClient
{
    private final static int CONNECTION_TIMEOUT = 30; // seconds
    private final static int WRITE_TIMEOUT = 600; // seconds
    private final static int READ_TIMEOUT = 600; // seconds

    private final String apiUrl;
    private final OkHttpClient client;
    private String token;
    private final String username;
    private final String password;
    private final String staticToken; // For token auth
    private final Map<String, String> proxySettings;
    private final AuthType authType;

    enum AuthType {
        BASIC,
        TOKEN
    }

    /**
     * Constructor for Fortify Hub API using Basic or Token authentication.
     */
    FortifyClient(
        final String apiUrl,
        final String username,
        final String password,
        final String staticToken,
        final AuthType authType,
        final Map<String, String> proxySettings
    ) {
        this.apiUrl = apiUrl;
        this.username = username;
        this.password = password;
        this.staticToken = staticToken;
        this.authType = authType;
        this.proxySettings = proxySettings;
        this.client = createClient();
    }

    /**
     * For Basic Auth, returns a Base64-encoded header. For Token, returns Bearer token.
     */
    // TODO drop basic auth
    public String getAuthHeader() {
        if (authType == AuthType.BASIC) {
        //    final String credentials = username + ":" + password;
            final String credentials = "rtorney@opentext.com:Microfocus+14";
            return "Basic " + java.util.Base64.getEncoder().encodeToString(credentials.getBytes());
        } else if (authType == AuthType.TOKEN) {
            return "FortifyToken " + staticToken;
        } else {
            throw new IllegalArgumentException("Unsupported authentication type: " + authType);
        }
    }

    private OkHttpClient createClient() {
        final OkHttpClient.Builder baseClient = new OkHttpClient().newBuilder()
            .connectTimeout(CONNECTION_TIMEOUT, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT, TimeUnit.SECONDS);

        if (proxySettings != null && !proxySettings.isEmpty()) {
            final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxySettings.get("host"),
                                                                                 Integer.valueOf(proxySettings.get("port"))));
            baseClient.proxy(proxy);
        }

        return baseClient.build();
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public OkHttpClient getClient() {
        return client;
    }
}
