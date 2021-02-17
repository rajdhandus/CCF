import Hashes from "jshashes";
import { KJUR, KEYUTIL, X509 } from 'jsrsasign';
import { Base64 } from "js-base64";
import { URL } from "core-js-pure/web/url"
import * as ccf from "../types/ccf";

interface Error {
  error: {
    code: string
    message: string
  }
}

interface FeedNamespace {
  
}

interface NamespaceRegisterRequest {
  issuer: string
}

interface ItemResponse {
  issuer: string
  subject: string
  seqno: number
  jwt: string
}

namespace kv {
  // "example.com" or "example.com/sub"
  export const Issuer = ccf.string
  
  // "example.com|item_a"
  // "|" is used as it is an illegal character in URLs
  export const FullFeedName = ccf.string
}

const feedNamespacesMap = new ccf.TypedKVMap(ccf.kv['feed_namespaces'], kv.Issuer, ccf.json<FeedNamespace>());
const feedItemMap = new ccf.TypedKVMap(ccf.kv['feed_item'], kv.FullFeedName, ccf.string);
const feedSeqnoMap = new ccf.TypedKVMap(ccf.kv['feed_seqno'], kv.FullFeedName, ccf.uint32);

// POST /register
export function registerNamespace(request: ccf.Request<NamespaceRegisterRequest>): ccf.Response<FeedNamespace> {
  const req = request.body.json();
  const issuer = req.issuer;
  /*let issuerUrl: URL

  try {
    issuerUrl = new URL(`https://${issuer}`)
  } catch (e) {
    return {
      statusCode: 400,
      body: {
        error: {
          code: 'InvalidInput',
          message: `https://<issuer> is not a valid URL: ${e}`
        }
      }
    };
  }
  if (issuerUrl.port || issuerUrl.username || issuerUrl.password || issuerUrl.search || issuerUrl.hash) {
    return {
      statusCode: 400,
      body: {
        error: {
          code: 'InvalidInput',
          message: `Issuer can only contain domain and path`
        }
      }
    };
  }
*/
  // TODO fetch certs (for now, rely on existing JWT signing key refresh of CCF)

  const isUpdate = feedNamespacesMap.has(issuer);
  const feedNamespace = {}
  feedNamespacesMap.set(issuer, feedNamespace);
  return {
    statusCode: isUpdate ? 200 : 201,
    body: feedNamespace
  }
}

// POST /submit
export function submit(request: ccf.Request): ccf.Response<ItemResponse | Error> {
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
  const payload = jws.payloadObj as any
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

  const issuer = payload['iss'];
  const subject = payload['sub'];
  const feedName = `${issuer}|${subject}`
  const feedNamespace = feedNamespacesMap.get(issuer);
  if (feedNamespace === undefined) {
    return {
      statusCode: 400,
      body: {
        error: {
          code: 'InvalidInput',
          message: "Feed namespace not found"
        }
      }
    };
  }
  
  const currentSeqno = feedSeqnoMap.get(feedName);
  const nextSeqno = currentSeqno === undefined ? 1 : currentSeqno + 1;

  const signingKeyId = header.kid;
  // Get the stored signing key to validate the token.
  const keysMap = new ccf.TypedKVMap(
    ccf.kv["public:ccf.gov.jwt.public_signing_keys"],
    ccf.string,
    ccf.typedArray(Uint8Array)
  );
  const publicKeyDer = keysMap.get(signingKeyId);
  if (publicKeyDer === undefined) {
    return {
      statusCode: 400,
      body: {
        error: {
          code: 'InvalidInput',
          message: "Signing key not found"
        }
      }
    };
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
    return {
      statusCode: 400,
      body: {
        error: {
          code: 'InvalidInput',
          message: "jwt validation failed"
        }
      }
    };
  }

  // Get the issuer associated to the signing key.
  const keyIssuerMap = new ccf.TypedKVMap(
    ccf.kv["public:ccf.gov.jwt.public_signing_key_issuer"],
    ccf.string,
    ccf.string
  );
  const keyIssuer = keyIssuerMap.get(signingKeyId);
  if (keyIssuer !== `https://${issuer}`) {
    return {
      statusCode: 400,
      body: {
        error: {
          code: 'InvalidInput',
          message: `url mismatch: ${keyIssuer} !== https://${issuer}`
        }
      }
    };
  }


  //new Hashes.SHA256().hex(body)

  feedSeqnoMap.set(feedName, nextSeqno);
  feedItemMap.set(feedName, body);

  return {
    statusCode: 201,
    body: {
      issuer: issuer,
      subject: subject,
      seqno: nextSeqno,
      jwt: body
    }
  }
}
