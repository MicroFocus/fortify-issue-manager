!not-ready-for-release!

#### Version Number
${version-number}

#### Breaking Changes
- US1030023: The Fortify SSC API is now used instead of the Fortify on Demand API.

| Old Environment Variable (FoD) | New Environment Variable (SSC) | Notes                                                |
|--------------------------------|--------------------------------|------------------------------------------------------|
| `FORTIFY_GRANT_TYPE`           | **Removed**                    | SSC uses token-based authentication                  |
| `FORTIFY_CLIENT_ID`            | **Removed**                    | No longer needed with SSC                            |
| `FORTIFY_CLIENT_SECRET`        | **Removed**                    | No longer needed with SSC                            |
| `FORTIFY_USERNAME`             | **Removed**                    | No longer needed with SSC                            |
| `FORTIFY_PASSWORD`             | **Removed**                    | No longer needed with SSC                            |
| `FORTIFY_SCOPE`                | **Removed**                    | Not applicable to SSC                                |
| **N/A**                        | `FORTIFY_TOKEN`                | **New** - SSC authentication token                   |
| `FORTIFY_API_URL`              | `FORTIFY_URL`                  | `FORTIFY_URL` is now used for both API and issue URL |
| `FORTIFY_ISSUE_URL`            | **Removed**                    | `FORTIFY_URL` is now used for both API and issue URL |
| `FORTIFY_RELEASE_FILTERS`      | `FORTIFY_RELEASE_IDS`          | Now requires specific release/version IDs            |
| `FORTIFY_ISSUE_FILTERS`        | `FORTIFY_ISSUE_QUERY`          | Now uses SSC query expression format                 |

See the [README](./README.md) for more details on each new environment variable

#### New Features
- None

#### Known Issues
- None
