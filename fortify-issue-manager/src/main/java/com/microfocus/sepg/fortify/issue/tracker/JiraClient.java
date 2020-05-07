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
package com.microfocus.sepg.fortify.issue.tracker;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.StringUtils;
import org.glassfish.jersey.internal.util.Base64;

import okhttp3.Authenticator;
import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

final class JiraClient
{
    private final static int CONNECTION_TIMEOUT = 30; // seconds
    private final static int WRITE_TIMEOUT = 600; // seconds
    private final static int READ_TIMEOUT = 600; // seconds

    private final String apiUrl;
    private final OkHttpClient client;

    private final String username;
    private final String password;

    private final int proxyPort;
    private final String proxyHost;

    private final String encodedAuth;

    JiraClient(final String username, final String password, final String apiUrl,
            final String proxyHost, final int proxyPort) {
        this.username = username;
        this.password = password;
        this.apiUrl = apiUrl;
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;

        client = createClient();

        final String auth = username + ":" + password;
        encodedAuth = Base64.encodeAsString(auth.getBytes());
    }

    private OkHttpClient createClient() {
        final OkHttpClient.Builder baseClient = new OkHttpClient().newBuilder()
                .connectTimeout(CONNECTION_TIMEOUT, TimeUnit.SECONDS)
                .writeTimeout(WRITE_TIMEOUT, TimeUnit.SECONDS)
                .readTimeout(READ_TIMEOUT, TimeUnit.SECONDS);

        if(StringUtils.isNotEmpty(proxyHost))
        {
            final Authenticator proxyAuthenticator = new Authenticator() {
                @Override public Request authenticate(final Route route, final Response response) throws IOException {
                     final String credential = Credentials.basic(username, password);
                     return response.request().newBuilder()
                         .header("Proxy-Authorization", credential)
                         .build();
                }
              };

              baseClient.proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort)))
                        .proxyAuthenticator(proxyAuthenticator);
        }
        return baseClient.build();
    }

    String getBasicAuthToken()
    {
        return encodedAuth;
    }

    String getApiUrl() {
        return apiUrl;
    }

    OkHttpClient getClient() {
        return client;
    }
}
