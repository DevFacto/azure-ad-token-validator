import axios, { AxiosError } from "axios";
import {
  Jwt,
  decode,
  JwtPayload,
  verify,
  JsonWebTokenError,
  JwtHeader,
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

type AzureAdTokenHeader = Omit<
  JwtHeader,
  "cty" | "crit" | "jku" | "x5u" | "x5c"
>;

type AzureAdTokenPayload =
  // aud
  // iss
  // iat : issued at
  // nbf : not before
  // exp : expiry
  // sub : user
  // jti
  Omit<JwtPayload, "jti"> & {
    idp?: string;
    aio?: string;
    acr?: "0" | "1";
    amr?: string[];
    appid?: string; // v1.0 only
    azp?: string; // v2.0 replacement for appid
    appidacr?: "0" | "1" | "2";
    azpacr?: "0" | "1" | "2";
    preferred_username?: string; // v2.0 only
    name?: string;
    scp?: string;
    roles?: string[];
    wids?: string[];
    groups?: string[];
    hasgroups?: boolean;
    oid?: string;
    tid?: string; // tenant id
    unique_name?: string; // v1.0 only
    uti?: string;
    rh?: string;
    ver?: "1.0" | "2.0";
  };

interface AzureAdToken {
  header: AzureAdTokenHeader;
  payload: AzureAdTokenPayload;
  signature: string;
}

export interface AzureAdTokenValidationResult {
  accessToken: string;
  decodedAccessToken: AzureAdToken | null;
  isValid: boolean;
  validationMessage?: string;
}

interface AzureAdOpenIdConnectMetadataDocument {
  jwks_uri: string;
}
interface AzureAdOpenIdConnectMetadataKeysDocument {
  keys: AzureAdKeyValue[];
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

    result.decodedAccessToken = {
      header: decodedAccessToken.header as AzureAdTokenHeader,
      payload: decodedAccessToken.payload as AzureAdTokenPayload,
      signature: decodedAccessToken.signature,
    };

    const publicKey = await this.getPublicKey(decodedAccessToken);

    if (!publicKey) {
      result.isValid = false;
      result.validationMessage = `Invalid key`;
      return result;
    } else {
      try {
        verify(
          accessToken,
          decodedAccessToken.header.alg.indexOf("RS") === 0
            ? `-----BEGIN CERTIFICATE-----\n${publicKey.x5c[0]}\n-----END CERTIFICATE-----`
            : publicKey.x5c[0],
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

    // azp in v2.0 and appid in v1.0
    const appId = (payload as JwtPayload).azp || (payload as JwtPayload).appid;

    try {
      const { data } =
        await axios.get<AzureAdOpenIdConnectMetadataKeysDocument>(
          `${this.metadata?.jwks_uri}?appid=${appId}`
        );
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
        (!!(tokenPayload.azp || tokenPayload.appid) &&
          allowedApplicationIds.indexOf(
            tokenPayload.azp || tokenPayload.appid
          ) >= 0),
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
