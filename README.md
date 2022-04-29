# azure-ad-token-validator

A simple, lightweight library for validating Azure AD auth tokens. Example use
case: Node.js API validating auth tokens from client apps in middleware.

```
npm install azure-ad-token-verify
```

### Usage

```javascript
const azureAdTokenValidator = new AzureAdTokenValidator({
  // required
  tenantId: "{your Azure AD tenant id}",
  audience: "{intended audience}", // ex. "api://{your API client ID}"
  metadataDocumentUri: "{uri of the discovery endpoint for your tenant}", // ex. https://login.microsoftonline.com/{your tenant id}/v2.0/.well-known/openid-configuration
  // optional
  allowedApplicationIds: [], // list of allowed client application IDs (guids)
  requiredScopes: [], // list of scopes that must be present in tokens (ex. ["Api.Connect"])
  validIssuers: [], // ex. ["https://sts.windows.net/{your tenant id}}/",]
});

const validationResult = await azureAdTokenValidator.validate("{token value}");
```

### ValidationResult

| Prop               | Value                                        |
| ------------------ | -------------------------------------------- |
| isValid            | `true` if token is valid, `false` if not     |
| validationMessage  | reason for validation failure                |
| accessToken        | string value of access token parameter       |
| decodedAccessToken | Jwt object representing decoded access token |
