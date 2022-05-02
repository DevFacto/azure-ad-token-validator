import axios from "axios";
import MockAdapter from "axios-mock-adapter";
const mock: MockAdapter = new MockAdapter(axios);

import { AzureAdTokenValidator } from "../src/AzureAdTokenValidator";
import sign from "jwt-encode";

describe("AzureAdTokenValidator:validate", () => {
  const secret = "secret";

  const metadataUri = "/metadata";
  const keysUri = `/keys`;
  const baseValidatorOptions = {
    metadataDocumentUri: metadataUri,
    audience: "api://28748804-910c-52c8-a22b-54c8a6148f16",
    tenantId: "75400737-17ad-5426-9e6b-df83ab52c0a1",
  };
  const baseTokenData = {
    alg: "HS256",
    sub: "1234567890",
    name: "John Doe",
    iat: new Date().getTime() / 1000,
    aud: baseValidatorOptions.audience,
    tid: baseValidatorOptions.tenantId,
    appid: "ce5da148-28fd-5850-84a6-592b046d3bf9",
    kid: "e4a44080-63e2-5fc0-b84a-7e94b3952db7",
  };

  describe("When token is valid", () => {
    const validator = new AzureAdTokenValidator(baseValidatorOptions);
    const data = {
      ...baseTokenData,
    };
    const jwt = sign(data, secret, {
      kid: data.kid,
    });

    const keysData = {
      jwks_uri: keysUri,
    };
    mock.onGet(metadataUri).reply(200, keysData);

    mock.onGet(`${keysData.jwks_uri}?appid=${data.appid}`).reply(200, {
      keys: [
        {
          kid: data.kid,
          use: "sig",
          x5t: data.kid,
          x5c: [secret],
        },
      ],
    });

    it("should validate", async () => {
      const result = await validator.validate(jwt);
      expect(result.validationMessage).toBeUndefined();
      expect(result.isValid).toBe(true);
    });
  });

  describe("When required scope is missing", () => {
    const validator = new AzureAdTokenValidator({
      ...baseValidatorOptions,
      requiredScopes: ["Api.Connect"],
    });

    const data = {
      ...baseTokenData,
      scp: "",
    };
    const jwt = sign(data, secret, {
      kid: data.kid,
    });

    const keysData = {
      jwks_uri: keysUri,
    };
    mock.onGet(metadataUri).reply(200, keysData);

    mock.onGet(`${keysData.jwks_uri}?appid=${data.appid}`).reply(200, {
      keys: [
        {
          kid: data.kid,
          use: "sig",
          x5t: data.kid,
          x5c: [secret],
        },
      ],
    });

    it("should fail", async () => {
      const result = await validator.validate(jwt);
      expect(result.validationMessage).toEqual("required scopes missing");
      expect(result.isValid).toBe(false);
    });
  });

  describe("When audience doesn't match", () => {
    const validator = new AzureAdTokenValidator({
      ...baseValidatorOptions,
      requiredScopes: ["Api.Connect"],
    });

    const data = {
      ...baseTokenData,
      scp: "",
      aud: "something else",
    };
    const jwt = sign(data, secret, {
      kid: data.kid,
    });

    const keysData = {
      jwks_uri: keysUri,
    };
    mock.onGet(metadataUri).reply(200, keysData);

    mock.onGet(`${keysData.jwks_uri}?appid=${data.appid}`).reply(200, {
      keys: [
        {
          kid: data.kid,
          use: "sig",
          x5t: data.kid,
          x5c: [secret],
        },
      ],
    });

    it("should fail", async () => {
      const result = await validator.validate(jwt);
      expect(result.validationMessage).toEqual(
        `jwt audience invalid. expected: ${baseValidatorOptions.audience}`
      );
      expect(result.isValid).toBe(false);
    });
  });
});
