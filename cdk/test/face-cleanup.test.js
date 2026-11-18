'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createCleanupHandler } = require('../lambda/face-cleanup');
const { fakeClient } = require('./helpers');

const NOW = 1_700_000_000_000;
const NOW_S = Math.floor(NOW / 1000);
const TABLE = 'test-table';
const COLLECTION = 'test-collection';

const remove = (pk, eventName = 'REMOVE') => ({ eventName, dynamodb: { Keys: { pk: { S: pk } } } });

test('removed registry items delete their face vectors', async () => {
  const rekognition = fakeClient({ DeleteFacesCommand: (input) => ({ DeletedFaces: input.FaceIds }) });
  const handler = createCleanupHandler({ rekognition, ddb: fakeClient(), collectionId: COLLECTION, tableName: TABLE });

  const result = await handler({
    Records: [remove('FACE#a'), remove('FACE#b'), remove('USAGE#a#1'), remove('FACE#c', 'INSERT'), remove('FACE#a')],
  });

  assert.deepEqual(result, { deleted: 2 });
  assert.deepEqual(rekognition.calls[0].input, { CollectionId: COLLECTION, FaceIds: ['a', 'b'] });
});

test('a batch with no face removals makes no calls', async () => {
  const rekognition = fakeClient();
  const handler = createCleanupHandler({ rekognition, ddb: fakeClient(), collectionId: COLLECTION, tableName: TABLE });
  assert.deepEqual(await handler({ Records: [remove('SESSION#x')] }), { deleted: 0 });
  assert.equal(rekognition.calls.length, 0);
});

test('the sweep deletes faces whose registry item is missing or expired', async () => {
  const pages = [
    { Faces: [{ FaceId: 'live' }, { FaceId: 'expired' }], NextToken: 'p2' },
    { Faces: [{ FaceId: 'orphan' }] },
  ];
  const rekognition = fakeClient({
    ListFacesCommand: (input) => (input.NextToken ? pages[1] : pages[0]),
    DeleteFacesCommand: (input) => ({ DeletedFaces: input.FaceIds }),
  });
  const ddb = fakeClient({
    BatchGetItemCommand: () => ({
      Responses: {
        [TABLE]: [
          { pk: { S: 'FACE#live' }, ttl: { N: String(NOW_S + 3600) } },
          { pk: { S: 'FACE#expired' }, ttl: { N: String(NOW_S - 1) } },
        ],
      },
    }),
  });
  const handler = createCleanupHandler({ rekognition, ddb, collectionId: COLLECTION, tableName: TABLE, now: () => NOW });

  assert.deepEqual(await handler({ sweep: true }), { scanned: 3, deleted: 2 });
  const deleted = rekognition.callsTo('DeleteFacesCommand').flatMap((c) => c.input.FaceIds);
  assert.deepEqual(deleted, ['expired', 'orphan']);
});

test('the sweep retries unprocessed BatchGetItem keys', async () => {
  let first = true;
  const ddb = fakeClient({
    BatchGetItemCommand: (input) => {
      if (first) {
        first = false;
        return { Responses: { [TABLE]: [] }, UnprocessedKeys: { [TABLE]: { Keys: input.RequestItems[TABLE].Keys } } };
      }
      return { Responses: { [TABLE]: [{ pk: { S: 'FACE#live' }, ttl: { N: String(NOW_S + 60) } }] } };
    },
  });
  const rekognition = fakeClient({ ListFacesCommand: () => ({ Faces: [{ FaceId: 'live' }] }) });
  const handler = createCleanupHandler({ rekognition, ddb, collectionId: COLLECTION, tableName: TABLE, now: () => NOW });

  assert.deepEqual(await handler({ sweep: true }), { scanned: 1, deleted: 0 });
  assert.equal(ddb.calls.length, 2);
});
