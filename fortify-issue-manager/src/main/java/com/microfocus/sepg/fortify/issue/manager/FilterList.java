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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

final class FilterList
{
    private Map<String, String> filters;

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
