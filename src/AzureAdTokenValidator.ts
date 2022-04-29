import axios, { AxiosError } from "axios";
import {
  Jwt,
  decode,
  JwtPayload,
  verify,
  JsonWebTokenError,
} from "jsonwebtoken";
import SimpleCache from "./SimpleCache";
import {
  SimpleValidationResult,
  SimpleValidationRule,
  validateRules,
} from "./SimpleValidator";

export interface AzureAdTokenValidationOptions {
  tenantId: string;
  audience: string;
  metadataDocumentUri: string;
  allowedApplicationIds?: string[];
  roles?: string[];
  requiredScopes?: string[];
  validIssuers?: string[];
}

export interface AzureAdTokenValidationResult {
  accessToken: string;
  decodedAccessToken: Jwt | null;
  isValid: boolean;
  validationMessage?: string;
}

interface AzureAdOpenIdConnectMetadataDocument {
  jwks_uri: string;
}

interface AzureAdKeyValue {
  kid: string;
  use: string; // "sig"
  x5t: string;
  x5c: string[];
}

const cache = new SimpleCache<AzureAdKeyValue>();

export class AzureAdTokenValidator {
  options: AzureAdTokenValidationOptions;
  metadata: AzureAdOpenIdConnectMetadataDocument | null = null;

  constructor(options: AzureAdTokenValidationOptions) {
    this.options = options;

    const { tenantId, audience } = this.options;
    if (!tenantId) {
      throw new Error('"tenantId" value was not provided');
    }
    if (!audience) {
      throw new Error('"audience" value was not provided');
    }
  }

  private loadMetadata = async () => {
    try {
      const { data } = await axios.get<AzureAdOpenIdConnectMetadataDocument>(
        this.options.metadataDocumentUri
      );
      this.metadata = data;
    } catch (error: unknown) {
      throwFormattedError(error);
    }
  };

  public validate = async (
    accessToken: string
  ): Promise<AzureAdTokenValidationResult> => {
    if (!this.metadata) {
      await this.loadMetadata();
    }

    const result: AzureAdTokenValidationResult = {
      accessToken,
      decodedAccessToken: null,
      isValid: true,
    };

    const decodedAccessToken = decode(accessToken, {
      json: true,
      complete: true,
    });

    if (!decodedAccessToken) {
      result.isValid = false;
      result.validationMessage = "The access token could not be decoded";
      return result;
    }

    result.decodedAccessToken = decodedAccessToken;

    const publicKey = await this.getPublicKey(decodedAccessToken);

    if (!publicKey) {
      result.isValid = false;
      result.validationMessage = `Invalid key`;
      return result;
    } else {
      try {
        verify(
          accessToken,
          `-----BEGIN CERTIFICATE-----\n${publicKey.x5c[0]}\n-----END CERTIFICATE-----`,
          {
            algorithms: [decodedAccessToken.header.alg as any],
            audience: this.options.audience,
            issuer: this.options.validIssuers,
          }
        );
      } catch (error: unknown) {
        if (error instanceof JsonWebTokenError) {
          result.isValid = false;
          result.validationMessage = error.message;
          return result;
        }
        throw error;
      }
    }

    const tokenValidationResult = validateAdditionalClaims(
      decodedAccessToken!.payload as JwtPayload,
      this.options
    );

    if (!tokenValidationResult.isValid) {
      result.isValid = false;
      result.validationMessage = tokenValidationResult.validationMessage;
      return result;
    }

    return result;
  };

  private getPublicKey = async ({
    header,
    payload,
  }: Jwt): Promise<AzureAdKeyValue | undefined> => {
    if (!header.kid) {
      return undefined;
    }

    const cachedKey = cache.getItem(header.kid);
    if (!!cachedKey) {
      return cachedKey;
    }

    try {
      const { data } = await axios.get<{
        keys: AzureAdKeyValue[];
      }>(`${this.metadata?.jwks_uri}?appid=${(payload as JwtPayload).appid}`);

      // Cache known keys so that we aren't spamming the discovery endpoints
      for (const publicKey of data.keys) {
        cache.setItem(header.kid, publicKey);
      }
    } catch (error: unknown) {
      throwFormattedError(error, "Error connecting to discovery keys endpoint");
    }

    return cache.getItem(header.kid);
  };
}

function validateAdditionalClaims(
  tokenPayload: JwtPayload,
  {
    tenantId,
    allowedApplicationIds,
    requiredScopes,
  }: AzureAdTokenValidationOptions
): SimpleValidationResult {
  const validators: SimpleValidationRule<JwtPayload>[] = [
    {
      validate: (tokenPayload) =>
        !!tokenPayload.tid && tokenPayload.tid === tenantId,
      invalidMessage: `tenantId does not match`,
    },
    {
      validate: (tokenPayload) =>
        !allowedApplicationIds ||
        allowedApplicationIds.length === 0 ||
        (!!tokenPayload.appid &&
          allowedApplicationIds.indexOf(tokenPayload.appid) >= 0),
      invalidMessage: `authenticated applicationId not in allowed list`,
    },
    {
      validate: (tokenPayload) => {
        const scopesAsArray: string[] = tokenPayload.scp?.split(" ") || [];

        return (
          !requiredScopes ||
          requiredScopes.length === 0 ||
          requiredScopes.every((s) => scopesAsArray.includes(s))
        );
      },
      invalidMessage: `required scopes missing`,
    },
  ];

  return validateRules(tokenPayload, validators);
}

const isAxiosError = <TError>(error: unknown): error is AxiosError<TError> =>
  !!error &&
  typeof error === "object" &&
  (error as AxiosError<TError>).isAxiosError;

function throwFormattedError(error: unknown, defaultErrorMessage?: string) {
  if (isAxiosError(error)) {
    if (error.response) {
      const { data, status } = error.response;
      throw new Error(JSON.stringify({ data, status }));
    }

    if (error.request) {
      const { data, status } = error.request;
      throw new Error(JSON.stringify({ data, status }));
    }
  }

  if (error instanceof Error) {
    throw new Error(error.message);
  }

  if (typeof error === "string") {
    throw new Error(error);
  }

  throw new Error(defaultErrorMessage);
}
