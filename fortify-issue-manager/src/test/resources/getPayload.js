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

// Fortify Severity Id --> Severity Info
var severityInfoLookup = {
    1: {jiraPriorityId: "5", jiraTitle: "Low Priority"},
    2: {jiraPriorityId: "4", jiraTitle: "Medium Priority"},
    3: {jiraPriorityId: "3", jiraTitle: "High Priority"},
    4: {jiraPriorityId: "2", jiraTitle: "Critical"}
};

function getPayload(fortifyApplicationName, issueSeverityId, issueCategory, jiraDescription) {
    var severityInfo = severityInfoLookup[issueSeverityId];

    return {
        fields: {
            project: {key: "ACME"},
            issuetype: {name: "Bug"},
            summary: "Fortify " + fortifyApplicationName + " scan: " + severityInfo.jiraTitle + " " + issueCategory + " issues",
            description: jiraDescription,
            priority: {id: severityInfo.jiraPriorityId}
        }
    };
}
