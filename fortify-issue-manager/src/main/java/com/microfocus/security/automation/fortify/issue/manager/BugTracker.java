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

import com.microfocus.security.automation.fortify.issue.manager.models.Vulnerability;
import com.microfocus.security.automation.fortify.issue.tracker.BugTrackerException;

import java.util.List;

public interface BugTracker
{
    /**
     * Create a bug with specified details.
     *
     * @param bugDetails Bug details
     * @return link to bug created
     * @throws BugTrackerException If a bug cannot be created in the bug tracker
     */
    String createBug(String bugDetails) throws BugTrackerException;

    String getIssueDescription(String issueBaseUrl, List<Vulnerability> vulnerabilities);

    String getOpenSourceIssueDescription(String issueBaseUrl, List<Vulnerability> vulnerabilities);
}
