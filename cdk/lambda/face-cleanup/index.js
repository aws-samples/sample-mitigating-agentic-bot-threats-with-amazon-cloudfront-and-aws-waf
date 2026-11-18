'use strict';

/**
 * Face-vector retention for the Rekognition collection.
 *
 * Two triggers:
 *   1. DynamoDB stream: when a "FACE#<faceId>" registry item is removed (TTL
 *      expiry or manual deletion, for example after an erasure request), delete
 *      that face from the collection.
 *   2. Daily schedule ({"sweep": true}): list every face in the collection and
 *      delete any whose registry item is missing or already past its TTL. This
 *      covers DynamoDB TTL lag and faces orphaned by a failed registry write.
 */

const { RekognitionClient, DeleteFacesCommand, ListFacesCommand } = require('@aws-sdk/client-rekognition');
const { DynamoDBClient, BatchGetItemCommand } = require('@aws-sdk/client-dynamodb');

const DELETE_BATCH = 4096; // DeleteFaces accepts up to 4096 face IDs
const READ_BATCH = 100; // BatchGetItem accepts up to 100 keys

function chunk(items, size) {
  const out = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

function createCleanupHandler({ rekognition, ddb, collectionId, tableName, now = Date.now }) {
  async function deleteFaces(faceIds) {
    let deleted = 0;
    for (const batch of chunk([...new Set(faceIds)], DELETE_BATCH)) {
      const result = await rekognition.send(new DeleteFacesCommand({ CollectionId: collectionId, FaceIds: batch }));
      deleted += (result.DeletedFaces || []).length;
    }
    return deleted;
  }

  async function registeredFaceIds(faceIds) {
    const nowSeconds = Math.floor(now() / 1000);
    const live = new Set();
    for (const batch of chunk(faceIds, READ_BATCH)) {
      let keys = batch.map((id) => ({ pk: { S: `FACE#${id}` } }));
      while (keys.length > 0) {
        const result = await ddb.send(new BatchGetItemCommand({
          RequestItems: { [tableName]: { Keys: keys, ProjectionExpression: 'pk, #ttl', ExpressionAttributeNames: { '#ttl': 'ttl' } } },
        }));
        for (const item of result.Responses?.[tableName] || []) {
          if (Number(item.ttl?.N || 0) > nowSeconds) live.add(item.pk.S.slice('FACE#'.length));
        }
        keys = result.UnprocessedKeys?.[tableName]?.Keys || [];
      }
    }
    return live;
  }

  async function sweep() {
    let nextToken;
    let deleted = 0;
    let scanned = 0;
    do {
      const page = await rekognition.send(new ListFacesCommand({ CollectionId: collectionId, MaxResults: 1000, NextToken: nextToken }));
      const ids = (page.Faces || []).map((f) => f.FaceId);
      scanned += ids.length;
      const live = await registeredFaceIds(ids);
      const expired = ids.filter((id) => !live.has(id));
      if (expired.length > 0) deleted += await deleteFaces(expired);
      nextToken = page.NextToken;
    } while (nextToken);
    return { scanned, deleted };
  }

  return async function handler(event) {
    if (event && event.sweep === true) {
      const result = await sweep();
      console.log(JSON.stringify({ event: 'face_sweep_complete', ...result }));
      return result;
    }

    const faceIds = (event.Records || [])
      .filter((r) => r.eventName === 'REMOVE')
      .map((r) => r.dynamodb?.Keys?.pk?.S || '')
      .filter((pk) => pk.startsWith('FACE#'))
      .map((pk) => pk.slice('FACE#'.length));

    if (faceIds.length === 0) return { deleted: 0 };
    // Throwing on failure lets the event source mapping retry, then route the
    // batch to the dead-letter queue.
    const deleted = await deleteFaces(faceIds);
    console.log(JSON.stringify({ event: 'faces_deleted', requested: faceIds.length, deleted }));
    return { deleted };
  };
}

let deployedHandler;
exports.handler = async (event) => {
  if (!deployedHandler) {
    deployedHandler = createCleanupHandler({
      rekognition: new RekognitionClient({}),
      ddb: new DynamoDBClient({}),
      collectionId: process.env.COLLECTION_ID,
      tableName: process.env.TABLE_NAME,
    });
  }
  return deployedHandler(event);
};

exports.createCleanupHandler = createCleanupHandler;
