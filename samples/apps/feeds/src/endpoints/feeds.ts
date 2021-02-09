import Hashes from "jshashes";
import { KJUR, KEYUTIL, X509 } from 'jsrsasign';
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

interface FeedNamespace {
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

// GET /feeds/{dnsName}/{itemName}/{seqno}
export function getItemIdentity(request: ccf.Request): ccf.Response<ItemIdentityResponse | Error> {
  const dnsName = request.params['dnsName'];
  const itemName = request.params['itemName'];
  const seqno = parseInt(request.params['seqno']);
  const feedName = `${dnsName}/${itemName}`
  const currentSeqno = feedSeqnoMap.get(feedName);
  if (currentSeqno === seqno) {
    return getLatestItemIdentity(request);
  }

  // TODO: how to do historic queries to get a specific seqno?
  throw new Error('not implemented');
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

  // TODO check if cert chain is valid

  const x509 = new X509();
  x509.readCertPEM(certPem);
  const x509Subject: Array<Array<any>> = (<any>x509).getSubject().array
  const cn = x509Subject.find(v => v[0].type == 'CN')[0].value
  // TODO handle wildcards
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
