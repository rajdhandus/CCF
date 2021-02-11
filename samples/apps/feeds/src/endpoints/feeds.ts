import Hashes from "jshashes";
import { KJUR, KEYUTIL, X509 } from 'jsrsasign';
import { Base64 } from "js-base64";
import * as ccf from "../types/ccf";

interface Error {
  error: {
    code: string
    message: string
  }
}

interface Auth {
  cert: string
}

interface JWKSItemAuth {
  // Signing certs are published at well-known url https://<namespace>/.well-known/openid-configuration
  type: 'jwks'
}

interface TLSCertItemAuth {
  // TLS cert is used for signing
  type: 'tlsCert'
}

type ItemAuth = JWKSItemAuth | TLSCertItemAuth

interface FeedNamespace {
  itemAuth: ItemAuth
  permissions: {
    owner: Auth
    writer: Auth
  };
}

interface ItemIdentity {
  hash: string
}

interface ItemIdentityResponse extends ItemIdentity {
  dnsName: string
  itemName: string
  seqno: number
}

namespace kv {
  // "example.com"
  export const DNSName = ccf.string
  
  // "example.com/item_a"
  export const FeedName = ccf.string
}

const feedNamespacesMap = new ccf.TypedKVMap(ccf.kv['feed_namespaces'], kv.DNSName, ccf.json<FeedNamespace>());
const feedItemIdentityMap = new ccf.TypedKVMap(ccf.kv['feed_item_identity'], kv.FeedName, ccf.json<ItemIdentity>());
const feedSeqnoMap = new ccf.TypedKVMap(ccf.kv['feed_seqno'], kv.FeedName, ccf.uint32);

// GET /feeds/{dnsName}
export function getFeedNamespace(request: ccf.Request): ccf.Response<FeedNamespace | Error> {
  const dnsName = request.params['dnsName'];
  const feedNamespace = feedNamespacesMap.get(dnsName);
  if (feedNamespace === undefined) {
    return {
      statusCode: 404,
      body: {
        error: {
          code: 'ResourceNotFound',
          message: "Feed namespace not found"
        }
      }
    };
  }
  return {
    statusCode: 200,
    body: feedNamespace
  };
}

// PUT /feeds/{dnsName}
export function setFeedNamespace(request: ccf.Request<FeedNamespace>): ccf.Response<FeedNamespace> {
  const dnsName = request.params['dnsName'];
  const feedNamespace = request.body.json();
  const isUpdate = feedNamespacesMap.has(dnsName);
  // TODO check if caller has "owner" permission
  feedNamespacesMap.set(dnsName, feedNamespace);
  return {
    statusCode: isUpdate ? 200 : 201,
    body: feedNamespace
  }
}

// TODO not really needed, we just care about the receipt
// GET /feeds/{dnsName}/{itemName}
export function getLatestItemIdentity(request: ccf.Request): ccf.Response<ItemIdentityResponse | Error> {
  const dnsName = request.params['dnsName'];
  const itemName = request.params['itemName'];
  const feedName = `${dnsName}/${itemName}`
  const itemIdentity = feedItemIdentityMap.get(feedName);
  if (itemIdentity === undefined) {
    return {
      statusCode: 404,
      body: {
        error: {
          code: 'ResourceNotFound',
          message: "Feed not found"
        }
      }
    };
  }
  const seqno = feedSeqnoMap.get(dnsName);
  return {
    statusCode: 200,
    body: {
      dnsName: dnsName,
      itemName: itemName,
      seqno: seqno,
      hash: itemIdentity.hash
    }
  }
}

// POST /feeds/{dnsName}/{itemName}
export function recordItemIdentity(request: ccf.Request): ccf.Response<ItemIdentityResponse | Error> {
  const dnsName = request.params['dnsName'];
  const itemName = request.params['itemName'];
  const feedName = `${dnsName}/${itemName}`
  const feedNamespace = feedNamespacesMap.get(dnsName);
  if (feedNamespace === undefined) {
    return {
      statusCode: 404,
      body: {
        error: {
          code: 'ResourceNotFound',
          message: "Feed namespace not found"
        }
      }
    };
  }
  
  // TODO check if caller has "writer" permission to namespace

  const currentSeqno = feedSeqnoMap.get(feedName);
  const nextSeqno = currentSeqno === undefined ? 1 : currentSeqno + 1;

  const body = request.body.text();
  
  let jws: KJUR.jws.JWS.JWSResult
  try {
    jws = KJUR.jws.JWS.parse(body);
  } catch (e) {
    return {
      statusCode: 400,
      body: {
        error: {
          code: 'InvalidInput',
          message: `Body is not a JWT: ${e}`
        }
      }
    };
  }
  const header = jws.headerObj as any
  if (!Array.isArray(header.x5c) || header.x5c.length === 0) {
    return {
      statusCode: 400,
      body: {
        error: {
          code: 'InvalidInput',
          message: `JWT is missing X.509 cert in header`
        }
      }
    };
  }
  const certX5c = header.x5c[0];
  const certPem = 
    '-----BEGIN CERTIFICATE-----\n' +
    certX5c +
    '\n-----END CERTIFICATE-----';
  const publicKey = KEYUTIL.getKey(certPem)
  const isValid = KJUR.jws.JWS.verifyJWT(body, <any>publicKey, <any>{
    alg: ['RS256'],
    // No trusted time, disable time validation.
    verifyAt: Date.parse('2000-01-01T00:00:00') / 1000,
    gracePeriod: 100 * 365 * 24 * 60 * 60
  });
  if (!isValid) {
    return {
      statusCode: 400,
      body: {
        error: {
          code: 'InvalidInput',
          message: `JWT validation failed`
        }
      }
    };
  }

  if (feedNamespace.itemAuth.type === 'jwks') {
    const signingKeyId = header.kid;
    // Get the stored signing key to validate the token.
    const keysMap = new ccf.TypedKVMap(
      ccf.kv["public:ccf.gov.jwt_public_signing_keys"],
      ccf.string,
      ccf.typedArray(Uint8Array)
    );
    const publicKeyDer = keysMap.get(signingKeyId);
    if (publicKeyDer === undefined) {
      throw new Error("signing key not found");
    }
    // jsrsasign can only load X.509 certs from PEM strings
    const publicKeyB64 = Base64.fromUint8Array(publicKeyDer);
    const publicKeyPem =
      "-----BEGIN CERTIFICATE-----\n" +
      publicKeyB64 +
      "\n-----END CERTIFICATE-----";
    const publicKey = KEYUTIL.getKey(publicKeyPem);

    // Validate the token signature.
    const valid = KJUR.jws.JWS.verifyJWT(
      body,
      <any>publicKey,
      <any>{
        alg: ["RS256"],
        // No trusted time, disable time validation.
        verifyAt: Date.parse("2020-01-01T00:00:00") / 1000,
        gracePeriod: 10 * 365 * 24 * 60 * 60,
      }
    );
    if (!valid) {
      throw new Error("jwt validation failed");
    }

    // Get the issuer associated to the signing key.
    const keyIssuerMap = new ccf.TypedKVMap(
      ccf.kv["public:ccf.gov.jwt_public_signing_key_issuer"],
      ccf.string,
      ccf.string
    );
    const keyIssuer = keyIssuerMap.get(signingKeyId);
    if (keyIssuer !== `https://${dnsName}`) {
      throw new Error(`url mismatch: ${keyIssuer} !== https://${dnsName}`);
    }
  } else if (feedNamespace.itemAuth.type == 'tlsCert') {
    // TODO check if cert chain is valid
    
    const x509 = new X509();
    x509.readCertPEM(certPem);
    const x509Subject: Array<Array<any>> = (<any>x509).getSubject().array
    // TODO check SANs
    // TODO handle wildcards
    const cn = x509Subject.find(v => v[0].type == 'CN')[0].value
    if (cn !== dnsName) {
      return {
        statusCode: 400,
        body: {
          error: {
            code: 'InvalidInput',
            message: `CN of signing certificate does not match feed: ${cn}`
          }
        }
      };
    }
  } else {
    throw new Error('invalid itemAuth type')
  }

  const item: ItemIdentity = {
    hash: new Hashes.SHA256().hex(body)
  }

  feedSeqnoMap.set(feedName, nextSeqno);
  feedItemIdentityMap.set(feedName, item);

  return {
    statusCode: 201,
    body: {
      dnsName: dnsName,
      itemName: itemName,
      seqno: nextSeqno,
      hash: item.hash
    }
  }
}
