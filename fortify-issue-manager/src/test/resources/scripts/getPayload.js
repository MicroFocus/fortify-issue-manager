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
//Fortify severity : Jira priority
var prioritiesLookupMap = {
      3: "3", // High
      4: "2"  // Critical
    };

//Application Id : Team
var teamOwnershipLookupMap = {
  113410: "20505", // Apollo Agent UI : SCMOD-Sigma
  111530: "20502", // Apollo BackEnd Services (Gamma) : SCMOD-Gamma
  111529: "20503", // Apollo BackEnd Services (Mu) : SCMOD-Mu
  111528: "20505", // Apollo FrontEnd Services : 
  111532: "20502", // Apollo Keycloak : SCMOD-Gamma
  111426: "20502"  // Apollo Workers - "SCMOD-Gamma"
};

//Information Security Category Name: Information Security Category Id
var informationSecurityCategoryLookupMap = {
  "FoD-SCA-Critical": "34559",
  "FoD-SCA-High": "34560",
  "FoD-OSS-Critical": "34561",
  "FoD-OSS-High": "34562"
};

function getTeamOwnership(category, applicationId) {
    if(category.contains("Log Forging"))
    { 
        return "20502"; // SCMOD-Gamma
    }
    else
    {
      return teamOwnershipLookupMap[applicationId];
    }
}

function getInformationSecurityCategory(severity, category) {
    if(category.contains("Open Source"))
    {
        if(severity == 4)
        {
            return informationSecurityCategoryLookupMap["FoD-OSS-Critical"];
        }
        else
        {
            return informationSecurityCategoryLookupMap["FoD-OSS-High"];
        }
            
    }
    else 
    {
        if(severity == 4)
        {
            return informationSecurityCategoryLookupMap["FoD-SCA-Critical"];
        }
        else
        {
            return informationSecurityCategoryLookupMap["FoD-SCA-High"];
        }
    }
}

function getPayload(applicationId, applicationName, severity, category, description) {
    
    var issue = {
      "fields": {
        "project": {
          "key": "SCMOD"
        },
        "issuetype": {
            "name": "Bug"
        },
        "summary": "Fortify " + applicationName + " scan: Resolve " + category + " issues",
        "description": description,
        "priority": {
          "id": prioritiesLookupMap[severity]
        },
        "customfield_15691": {
            "id": "20614" // Impact(s) : Security Issue
        },
        "components": [
          {
            "name": "Fod: " + applicationName // TODO: get the name fixed to FoD
          }
        ],
        "versions": [  // Affects Version/s
          {
            "name": "3.2" //3.3
          }
        ],
        "fixVersions": [
          {
            "name": "3.2" //3.3
          }
        ],
        // "customfield_10543": getInformationSecurityCategory(severity, category), //TODO: Information Security Category
        "customfield_10947": "SCMOD-6608", // Epic link -8803
        "customfield_12362": { // Team(s)
            "id": getTeamOwnership(category, applicationId)
        }        
      }
    };
    return JSON.stringify(issue);

}
