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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

final class FilterList
{
    private final Map<String, String> filters;

    public FilterList()
    {
        this.filters = new HashMap<>();
    }

    public FilterList addFilter(final String key, final String value)
    {
        this.filters.put(key, value);
        return this;
    }

    public FilterList addFilter(final String key, final int value)
    {
        this.filters.put(key, Integer.toString(value));
        return this;
    }

    public FilterList addFilter(final String key, final boolean value)
    {
        this.filters.put(key, Boolean.toString(value));
        return this;
    }

    public FilterList removeFilter(final String key)
    {
        if (filters.containsKey(key)) {
            filters.remove(key);
        }
        return this;
    }

    @Override
    public String toString()
    {
        final Iterator<Map.Entry<String, String>> iterator = filters.entrySet().iterator();

        final List<String> list = new ArrayList<>();
        while (iterator.hasNext()) {
            final Map.Entry<String, String> filter = iterator.next();
            list.add(filter.getKey() + ":" + filter.getValue());
            iterator.remove();
        }

        return String.join("+", list);
    }
}
