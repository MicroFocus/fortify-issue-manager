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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

final class FilterList
{
    private final Map<String, String> filters;

    public FilterList() {
        this.filters = new HashMap<>();
    }

    public FilterList addFilter(String key, String value) {
        this.filters.put(key, value);
        return this;
    }

    public FilterList addFilter(String key, int value) {
        this.filters.put(key, Integer.toString(value));
        return this;
    }

    public FilterList addFilter(String key, boolean value) {
        this.filters.put(key, Boolean.toString(value));
        return this;
    }

    public FilterList removeFilter(String key) {
        if (filters.containsKey(key))
            filters.remove(key);
        return this;
    }

    public String toString() {

        Iterator<Map.Entry<String, String>> iterator = filters.entrySet().iterator();

        List<String> list = new ArrayList<>();
        while (iterator.hasNext()) {
            Map.Entry<String, String> filter = iterator.next();
            list.add(filter.getKey() + ":" + filter.getValue());
            iterator.remove();
        }

        return String.join("+", list);
    }
}
