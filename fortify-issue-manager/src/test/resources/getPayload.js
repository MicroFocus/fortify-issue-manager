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

//Fortify severity : Jira priority

var prioritiesLookupMap = {
      3: "3", // High
      4: "2"  // Critical
};

//Fortify severity : Jira title

var titleLookupMap = {
      3: "High Priority", // High
      4: "Critical"       // Critical
};

function getPayload(applicationId, applicationName, severity, category, description) {
    return {
      fields: {
        project: {
          key: "ACME"
        },
        issuetype: {
            name: "Bug"
        },
        summary: "Fortify " + applicationName + " scan: " + titleLookupMap[severity] + " " + category + " issues",
        description: description,
        priority: {
          id: prioritiesLookupMap[severity]
        }
      }
    };
}
