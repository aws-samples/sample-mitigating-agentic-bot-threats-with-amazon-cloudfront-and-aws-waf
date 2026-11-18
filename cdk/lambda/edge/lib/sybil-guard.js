'use strict';

const { SearchFacesByImageCommand, IndexFacesCommand } = require('@aws-sdk/client-rekognition');
const { PutItemCommand, UpdateItemCommand } = require('@aws-sdk/client-dynamodb');

/**
 * Per-face verification limit for Face Liveness.
 *
 * Liveness checks that a live person is in front of the camera. It does not
 * check whether that person has verified before. Without this module, a small
 * group of real people could clear liveness for many agent-driven browser
 * sessions. This module:
 *
 *   1. Searches the face collection with SearchFacesByImage.
 *   2. Enrolls the face with IndexFaces when there is no match.
 *   3. Limits verifications per face per window in DynamoDB.
 *
 * This raises the cost of a sybil attack; it is not a hard per-person limit:
 *   - Windows are fixed and aligned to the Unix epoch, not rolling. With
 *     24-hour windows every count resets at 00:00 UTC.
 *   - A person whose face matches below faceMatchThreshold (angle, lighting,
 *     glasses), or who runs two first-time checks at once, can be enrolled
 *     more than once, each with its own count.
 *
 * Rekognition stores a face feature vector, not the image. The DynamoDB
 * "FACE#<faceId>" item carries a TTL; when it expires, the face-cleanup function
 * deletes the vector from the collection (see lambda/face-cleanup).
 *
 * Table items (partition key "pk"):
 *   SESSION#<livenessSessionId>   single-use marker for a liveness session
 *   FACE#<faceId>                 face registry item, drives retention
 *   USAGE#<faceId>#<windowIndex>  verification counter for one window
 */
function createSybilGuard({ rekognition, ddb, config, now = Date.now }) {
  const epochSeconds = (ms) => Math.floor(ms / 1000);

  /** Mark a liveness session as used. Returns false when it was already used. */
  async function consumeSession(sessionId) {
    try {
      await ddb.send(new PutItemCommand({
        TableName: config.tableName,
        Item: {
          pk: { S: `SESSION#${sessionId}` },
          ttl: { N: String(epochSeconds(now()) + 3600) },
        },
        ConditionExpression: 'attribute_not_exists(pk)',
      }));
      return true;
    } catch (error) {
      if (error.name === 'ConditionalCheckFailedException') return false;
      throw error;
    }
  }

  async function findOrEnrollFace(imageBytes) {
    let matchedFaceId;
    try {
      const search = await rekognition.send(new SearchFacesByImageCommand({
        CollectionId: config.collectionId,
        Image: { Bytes: imageBytes },
        FaceMatchThreshold: config.faceMatchThreshold,
        MaxFaces: 1,
        QualityFilter: 'AUTO',
      }));
      matchedFaceId = search.FaceMatches?.[0]?.Face?.FaceId;
    } catch (error) {
      // SearchFacesByImage returns InvalidParameterException when no face is detected.
      if (error.name === 'InvalidParameterException') return { faceId: null, reason: 'no_face_detected' };
      throw error;
    }
    if (matchedFaceId) return { faceId: matchedFaceId, enrolled: false };

    const indexed = await rekognition.send(new IndexFacesCommand({
      CollectionId: config.collectionId,
      Image: { Bytes: imageBytes },
      MaxFaces: 1,
      QualityFilter: 'AUTO',
      DetectionAttributes: ['DEFAULT'],
    }));
    const faceId = indexed.FaceRecords?.[0]?.Face?.FaceId;
    if (!faceId) return { faceId: null, reason: 'face_quality_too_low' };
    return { faceId, enrolled: true };
  }

  /** Create or refresh the registry item. Retention slides with each verification. */
  async function touchFace(faceId) {
    const nowMs = now();
    await ddb.send(new UpdateItemCommand({
      TableName: config.tableName,
      Key: { pk: { S: `FACE#${faceId}` } },
      UpdateExpression: 'SET #ttl = :ttl, lastVerifiedAt = :now',
      ExpressionAttributeNames: { '#ttl': 'ttl' },
      ExpressionAttributeValues: {
        ':ttl': { N: String(epochSeconds(nowMs) + config.faceRetentionDays * 86400) },
        ':now': { N: String(epochSeconds(nowMs)) },
      },
    }));
  }

  /** Atomically count a verification. Returns false when the face is over its limit for this fixed window. */
  async function recordVerification(faceId) {
    const windowMs = config.verificationWindowHours * 3600 * 1000;
    const windowIndex = Math.floor(now() / windowMs);
    try {
      await ddb.send(new UpdateItemCommand({
        TableName: config.tableName,
        Key: { pk: { S: `USAGE#${faceId}#${windowIndex}` } },
        UpdateExpression: 'ADD #count :one SET #ttl = :ttl',
        ConditionExpression: 'attribute_not_exists(#count) OR #count < :max',
        ExpressionAttributeNames: { '#count': 'verifications', '#ttl': 'ttl' },
        ExpressionAttributeValues: {
          ':one': { N: '1' },
          ':max': { N: String(config.maxVerificationsPerFace) },
          ':ttl': { N: String(epochSeconds((windowIndex + 2) * windowMs)) },
        },
      }));
      return true;
    } catch (error) {
      if (error.name === 'ConditionalCheckFailedException') return false;
      throw error;
    }
  }

  /**
   * Decide whether the live person in `imageBytes` may receive another verified
   * session. Returns { allowed, reason?, enrolled? }. The face ID is never
   * returned to the browser.
   */
  async function evaluate(imageBytes) {
    const face = await findOrEnrollFace(imageBytes);
    if (!face.faceId) return { allowed: false, reason: face.reason };

    // Write the registry item before counting, so every enrolled face is
    // tracked for retention even if it is later refused.
    await touchFace(face.faceId);
    const withinCap = await recordVerification(face.faceId);
    if (!withinCap) return { allowed: false, reason: 'verification_limit_reached', enrolled: face.enrolled };
    return { allowed: true, enrolled: face.enrolled };
  }

  return { consumeSession, evaluate };
}

module.exports = { createSybilGuard };
