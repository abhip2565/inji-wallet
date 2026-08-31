import {
  createSignatureECK1,
  createSignatureECR1,
  createSignatureED,
  createSignatureRSA,
  fetchKeyPair,
} from '../cryptoutil/cryptoUtil';
import {base64ToByteArray, canonicalize, parseJSON} from '../Utils';
import getAllConfigurations, {CACHED_API} from '../api';
import {JWT_ALG_TO_KEY_TYPE} from '../constants';
import {SignatureAlgorithms} from '../cryptoutil/KeyTypes';
import {UnsignedVPToken, VPTokenSigningResult} from './openid4vp.types';
import {defaultWalletConfig} from './walletConfig/WalletConfig';
import forge from 'node-forge';

export async function getWalletConfig() {
  const config = await getAllConfigurations();
  let walletConfig = config.openid4vpWalletConfig;
  if (!walletConfig) {
    console.warn(
      'There is no wallet configuration available in the config. Using default wallet configuration.',
    );
    walletConfig = {...defaultWalletConfig};
  } else {
    walletConfig = parseJSON(walletConfig);
  }

  walletConfig['validate_trusted_verifier'] =
    config.openid4vpClientValidation === 'true';

  try {
    const trustedVerifiersResponse =
      await CACHED_API.fetchTrustedVerifiersList();
    walletConfig['trusted_verifiers'] =
      trustedVerifiersResponse.response.verifiers;
  } catch (e) {
    console.warn(
      'Error fetching trusted verifiers, falling back to default: ',
      e,
    );
    walletConfig['trusted_verifiers'] = [];
  }

  return walletConfig;
}

export const jsonLdCanonicalize = async (data: string) => {
  const parsedData = JSON.parse(data);
  const canonicalized = await canonicalize(parsedData);
  if (!canonicalized) {
    throw new Error('Canonicalized data to sign is undefined');
  }
  return canonicalized;
};

/**
 *
 * unsignedVPTokens : [{
 *   format: 'ldp_vc' | 'mso_mdoc' | 'vc_sd_jwt' | 'dc_sd_jwt',
 *   holderKeyReference: string,
 *   signatureAlgorithm: string,
 *   dataToSign: string
 * }]
 * @param unSignedVpTokens
 */
export const signDataForVpPreparation = async (
  unSignedVpTokens: Array<UnsignedVPToken>,
): Promise<Array<VPTokenSigningResult>> => {
  const keyTypeToKeysPromise: Record<string, Promise<any>> = {};

  const getKeyInfo = async (keyType: string) => {
    if (!keyTypeToKeysPromise[keyType]) {
      keyTypeToKeysPromise[keyType] = fetchKeyPair(keyType);
    }

    return keyTypeToKeysPromise[keyType];
  };

  const result: Promise<VPTokenSigningResult>[] = unSignedVpTokens.map(
    async unsignedVPToken => {
      let signature: string | undefined = '';
      const payload: string = unsignedVPToken.dataToSign;
      const signatureAlgorithm: string = unsignedVPToken.signatureAlgorithm;

      validateHolderAlgorithm(
        unsignedVPToken.holderKeyReference,
        signatureAlgorithm,
      );

      const keyType =
        JWT_ALG_TO_KEY_TYPE[
          signatureAlgorithm as keyof typeof JWT_ALG_TO_KEY_TYPE
        ];
      const key = await getKeyInfo(keyType);
      signature = await signData(
        key.privateKey,
        payload, // Payload is in base64 url encoded form - decode it before signing
        signatureAlgorithm,
      );
      if (
        ['EdDSA', 'ES256'].includes(signatureAlgorithm) &&
        unsignedVPToken.dataToSign &&
        base64ToByteArray(unsignedVPToken.dataToSign).length === 64 &&
        base64ToByteArray(signature).length !== 64
      ) {
        throw new Error(
          'Data Integrity Ed25519 and P-256 signatures must be exactly 64 bytes',
        );
      }
      return {
        signedData: signature,
        id: unsignedVPToken.id,
      } as VPTokenSigningResult;
    },
  );

  const vpTokenSigningResults = await Promise.all(result);
  return vpTokenSigningResults as Array<VPTokenSigningResult>;
};

function validateHolderAlgorithm(
  holderKeyReference: string,
  algorithm: string,
) {
  if (!holderKeyReference?.startsWith('did:jwk:')) return;
  const encoded = holderKeyReference
    .replace('did:jwk:', '')
    .split('#')[0]
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  try {
    const jwk = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
    const holderAlgorithm =
      jwk.alg ??
      (jwk.kty === 'OKP' && jwk.crv === 'Ed25519'
        ? 'EdDSA'
        : jwk.kty === 'EC' && jwk.crv === 'P-256'
        ? 'ES256'
        : undefined);
    if (holderAlgorithm && holderAlgorithm !== algorithm) {
      throw new Error(
        'The selected signing key does not match the VC holder key',
      );
    }
  } catch (error) {
    if ((error as Error).message.includes('does not match')) throw error;
    throw new Error('Unable to validate the VC holder key');
  }
}

async function signData(
  privateKey: string,
  base64EncodedPayload: string,
  keyType: string,
) {
  const payloadBytes: Uint8Array = base64ToByteArray(base64EncodedPayload);

  switch (keyType) {
    case SignatureAlgorithms.RS256:
      return createSignatureRSA(
        privateKey,
        forge.util.binary.raw.encode(payloadBytes),
      );
    case SignatureAlgorithms.ES256:
      return createSignatureECR1(privateKey, payloadBytes);
    case SignatureAlgorithms.ES256K:
      return createSignatureECK1(privateKey, payloadBytes);
    case SignatureAlgorithms.EdDSA: {
      return createSignatureED(privateKey, payloadBytes);
    }
    default:
      throw new Error(`Unsupported signature algorithm: ${keyType}`);
  }
}

/**
 * @param path
 * @param fullPayload
 *
 * Converts a Claim Path Pointer (array of strings/numbers/null) to one or more JSONPath strings
 *
 * Input -> output examples:
 *
 * ['credentialSubject', null, 'givenName'] -> 'credentialSubject[*].givenName'
 *
 * ['credentialSubject', 0, 'givenName'] -> 'credentialSubject[0].givenName'
 *
 * ['credentialSubject', 'degree', 'ug'] -> 'credentialSubject.degree.ug'
 */
export function claimPathPointersToJsonPath(
  path: Array<string | number | null>,
): string {
  let currentPath = '';

  for (const token of path) {
    // Object property
    if (typeof token === 'string') {
      currentPath = currentPath ? `${currentPath}.${token}` : token;

      continue;
    }

    // Exact array index
    if (typeof token === 'number') {
      currentPath = `${currentPath}[${token}]`;

      continue;
    }

    // Wildcard array
    if (token === null) {
      currentPath = `${currentPath}[*]`;
    }
  }

  return currentPath;
}

export const isDcqlFlow = (vpRequest: Record<string, unknown>) =>
  (vpRequest as Record<string, unknown>)['dcql_query'] !== undefined;
