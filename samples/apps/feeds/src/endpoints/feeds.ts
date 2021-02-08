import * as ccf from "../types/ccf";

interface Feed {
  //permissions: any;
}

const feedsMap = new ccf.TypedKVMap(ccf.kv['feeds'], ccf.string, ccf.json<Feed>());

export function getFeed(request: ccf.Request): ccf.Response<Feed> {
  const id = request.params['feedId'];
  if (!feedsMap.has(id)) {
    return {
      statusCode: 404,
    };
  }
  return {
    body: feedsMap.get(id),
  };
}
