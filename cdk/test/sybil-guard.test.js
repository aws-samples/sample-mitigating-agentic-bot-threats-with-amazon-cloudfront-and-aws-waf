'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSybilGuard } = require('../lambda/edge/lib/sybil-guard');
const { CONFIG, AwsError, fakeClient } = require('./helpers');

const NOW = 1_700_000_000_000;
const IMAGE = new Uint8Array([1, 2, 3]);
const WINDOW = Math.floor(NOW / (24 * 3600 * 1000));

function setup({ search, index, usage } = {}) {
  const rekognition = fakeClient({
    SearchFacesByImageCommand: () => {
      if (search instanceof Error) throw search;
      return search ?? { FaceMatches: [] };
    },
    IndexFacesCommand: () => index ?? { FaceRecords: [{ Face: { FaceId: 'new-face' } }] },
  });
  const ddb = fakeClient({
    PutItemCommand: () => ({}),
    UpdateItemCommand: (input) => {
      if (input.Key.pk.S.startsWith('USAGE#') && usage instanceof Error) throw usage;
      return {};
    },
  });
  const guard = createSybilGuard({ rekognition, ddb, config: CONFIG, now: () => NOW });
  return { guard, rekognition, ddb };
}

test('a returning face is matched, not enrolled again', async () => {
  const { guard, rekognition, ddb } = setup({ search: { FaceMatches: [{ Similarity: 99.1, Face: { FaceId: 'known-face' } }] } });
  assert.deepEqual(await guard.evaluate(IMAGE), { allowed: true, enrolled: false });

  const search = rekognition.callsTo('SearchFacesByImageCommand')[0].input;
  assert.deepEqual(search, {
    CollectionId: CONFIG.collectionId,
    Image: { Bytes: IMAGE },
    FaceMatchThreshold: 95,
    MaxFaces: 1,
    QualityFilter: 'AUTO',
  });
  assert.equal(rekognition.callsTo('IndexFacesCommand').length, 0);

  const keys = ddb.callsTo('UpdateItemCommand').map((c) => c.input.Key.pk.S);
  assert.deepEqual(keys, ['FACE#known-face', `USAGE#known-face#${WINDOW}`]);
});

test('a new face is enrolled with IndexFaces', async () => {
  const { guard, rekognition } = setup();
  assert.deepEqual(await guard.evaluate(IMAGE), { allowed: true, enrolled: true });
  const index = rekognition.callsTo('IndexFacesCommand')[0].input;
  assert.equal(index.MaxFaces, 1);
  assert.equal(index.QualityFilter, 'AUTO');
  assert.equal(index.ExternalImageId, undefined);
});

test('the registry item carries the retention TTL', async () => {
  const { guard, ddb } = setup();
  await guard.evaluate(IMAGE);
  const registry = ddb.callsTo('UpdateItemCommand').find((c) => c.input.Key.pk.S === 'FACE#new-face').input;
  assert.equal(registry.ExpressionAttributeValues[':ttl'].N, String(Math.floor(NOW / 1000) + 30 * 86400));
});

test('the usage counter is capped atomically per window', async () => {
  const { guard, ddb } = setup();
  await guard.evaluate(IMAGE);
  const usage = ddb.callsTo('UpdateItemCommand').find((c) => c.input.Key.pk.S.startsWith('USAGE#')).input;
  assert.equal(usage.UpdateExpression, 'ADD #count :one SET #ttl = :ttl');
  assert.equal(usage.ConditionExpression, 'attribute_not_exists(#count) OR #count < :max');
  assert.equal(usage.ExpressionAttributeValues[':max'].N, '5');
});

test('a face over its cap is refused', async () => {
  const { guard } = setup({
    search: { FaceMatches: [{ Face: { FaceId: 'busy-face' } }] },
    usage: new AwsError('ConditionalCheckFailedException'),
  });
  assert.deepEqual(await guard.evaluate(IMAGE), { allowed: false, reason: 'verification_limit_reached', enrolled: false });
});

test('an image with no detectable face is refused without writing anything', async () => {
  const { guard, ddb } = setup({ search: new AwsError('InvalidParameterException') });
  assert.deepEqual(await guard.evaluate(IMAGE), { allowed: false, reason: 'no_face_detected' });
  assert.equal(ddb.calls.length, 0);
});

test('a face too poor to index is refused', async () => {
  const { guard } = setup({ index: { FaceRecords: [], UnindexedFaces: [{ Reasons: ['LOW_SHARPNESS'] }] } });
  assert.deepEqual(await guard.evaluate(IMAGE), { allowed: false, reason: 'face_quality_too_low' });
});

test('consumeSession is single-use', async () => {
  const ddb = fakeClient({ PutItemCommand: () => { throw new AwsError('ConditionalCheckFailedException'); } });
  const guard = createSybilGuard({ rekognition: fakeClient(), ddb, config: CONFIG, now: () => NOW });
  assert.equal(await guard.consumeSession('sid'), false);
  assert.equal(ddb.calls[0].input.ConditionExpression, 'attribute_not_exists(pk)');
  assert.equal(ddb.calls[0].input.Item.pk.S, 'SESSION#sid');
});

test('unexpected AWS errors propagate', async () => {
  const { guard } = setup({ search: new AwsError('ThrottlingException') });
  await assert.rejects(guard.evaluate(IMAGE), { name: 'ThrottlingException' });
});
