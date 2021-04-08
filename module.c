#define SESSION_ID_DICTIONARY "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define SESSION_ID_DICTIONARY_STRLEN strlen(SESSION_ID_DICTIONARY)
#define SESSION_ID_STRLEN (size_t)16 // SESSION_ID_DICTIONARY_STRLEN ^ 16 possible combinations.

// The signature is encoded as hex string.
// Each byte uses 2 characters. 256 bits (SHA-256) = 32 bytes. 32 bytes * 2 = 64 bytes.
#define SIGNATURE_STRLEN (size_t)64

#define SESSION_ENCODING_VERSION (uint8_t)1

// The token version is used for future token compatibilities.
#define TOKEN_VERSION "v1"
#define TOKEN_VERSION_STRLEN strlen(TOKEN_VERSION)
// TOKEN_VERSION_STRLEN + 1 dot + SESSION_ID_STRLEN + 1 dot + SIGNATURE_STRLEN.
#define TOKEN_STRLEN (size_t)(TOKEN_VERSION_STRLEN + 1 + SESSION_ID_STRLEN + 1 + SIGNATURE_STRLEN)

#define PAYLOAD_NAME_MAX_STRLEN (size_t)200
#define PAYLOAD_DATA_MAX_STRLEN (size_t)1e6 * 8 // 8 MB.

#include <string.h>

#include "sodium.h"
#include "redismodule.h"
#include "rmutil/util.h"


void generatePseudoRandomString(char *generatedStr) {
  uint8_t buf[SESSION_ID_STRLEN];
  randombytes_buf(buf, SESSION_ID_STRLEN);
  for (uint16_t i = 0; i < SESSION_ID_STRLEN; i++)
    generatedStr[i] =
        SESSION_ID_DICTIONARY[buf[i] % SESSION_ID_DICTIONARY_STRLEN];
}

void signData(const unsigned char *key, const size_t keyLen,
              const unsigned char *data, const size_t dataLen,
              char *signature) {
  unsigned char signatureHash[crypto_auth_hmacsha256_BYTES];
  crypto_auth_hmacsha256_state state;
  crypto_auth_hmacsha256_init(&state, key, keyLen);
  crypto_auth_hmacsha256_update(&state, data, dataLen);
  crypto_auth_hmacsha256_final(&state, signatureHash);
  sodium_bin2hex(signature, SIGNATURE_STRLEN + 1, signatureHash,
                 32); // 32 bytes = 256 bits.
}

void parseToken(const char *token, char *tokenVersion, char *sessionId,
                char *signature) {
  uint8_t i = 0;
  uint8_t ti = 0;
  for (i = 0; i < TOKEN_VERSION_STRLEN; i++, ti++)
    tokenVersion[i] = token[ti];
  tokenVersion[TOKEN_VERSION_STRLEN] = '\0';
  ti++;
  for (i = 0; i < SESSION_ID_STRLEN; i++, ti++)
    sessionId[i] = token[ti];
  sessionId[SESSION_ID_STRLEN] = '\0';
  ti++;
  for (i = 0; i < SIGNATURE_STRLEN; i++, ti++)
    signature[i] = token[ti];
  signature[SIGNATURE_STRLEN] = '\0';
}



int EndCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 3)
    return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  // Extract <sign_key> and validate it.
  size_t signKeyLen;
  const char *signKey = RedisModule_StringPtrLen(argv[1], &signKeyLen);
  if (signKeyLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<sign_key> must have at least one character");

  // Extract <token> and validate it.
  size_t tokenLen;
  const char *token = RedisModule_StringPtrLen(argv[2], &tokenLen);
  if (tokenLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<token> must have at least one character");
  else if (tokenLen != TOKEN_STRLEN)
    return RedisModule_ReplyWithError(ctx, "<token> format is invalid");

  // Parse the token.
  char tokenVersion[TOKEN_VERSION_STRLEN + 1];
  char sessionId[SESSION_ID_STRLEN + 1];
  char signature[SIGNATURE_STRLEN + 1];
  parseToken(token, tokenVersion, sessionId, signature);

  // Recreate the signature of the session id and compare with the signature
  // contained in the token.
  char signatureCheck[SIGNATURE_STRLEN + 1];
  signData((const unsigned char *)signKey, signKeyLen,
           (const unsigned char *)sessionId, SESSION_ID_STRLEN, signatureCheck);
  if (strncmp(signature, signatureCheck, SIGNATURE_STRLEN) != 0)
    return RedisModule_ReplyWithError(
        ctx, "the signature contained in <token> is invalid");

  // Check if the signature is the same stored in the session.
  RedisModuleString *sessionSignatureKeyStr =
      RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", sessionId);
  RedisModuleKey *redisKey = RedisModule_OpenKey(
      ctx, sessionSignatureKeyStr, REDISMODULE_READ | REDISMODULE_WRITE);
  if (RedisModule_KeyType(redisKey) != REDISMODULE_KEYTYPE_STRING) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the session id contained in <token> does not exist");
  }
  size_t signatureStoredLen;
  char *signatureStored =
      RedisModule_StringDMA(redisKey, &signatureStoredLen, REDISMODULE_READ);
  if (strncmp(signature, signatureStored, SIGNATURE_STRLEN) != 0) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the signature contained in <token> seems to be valid, but is "
             "different from the stored signature in the session");
  }

  // Delete the signature.
  RedisModule_DeleteKey(redisKey);
  RedisModule_CloseKey(redisKey);

  // Delete the payloads.
  RedisModuleString *sessionPayloadsKeyStr =
      RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", sessionId);
  redisKey = RedisModule_OpenKey(ctx, sessionPayloadsKeyStr, REDISMODULE_WRITE);
  if (RedisModule_KeyType(redisKey) != REDISMODULE_KEYTYPE_EMPTY)
    RedisModule_DeleteKey(redisKey);
  RedisModule_CloseKey(redisKey);

  RedisModule_ReplyWithSimpleString(ctx, "OK");
  return REDISMODULE_OK;
}


int ExpireCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 4)
    return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  // Extract <sign_key> and validate it.
  size_t signKeyLen;
  const char *signKey = RedisModule_StringPtrLen(argv[1], &signKeyLen);
  if (signKeyLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<sign_key> must have at least one character");

  // Extract <token> and validate it.
  size_t tokenLen;
  const char *token = RedisModule_StringPtrLen(argv[2], &tokenLen);
  if (tokenLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<token> must have at least one character");
  else if (tokenLen != TOKEN_STRLEN)
    return RedisModule_ReplyWithError(ctx, "<token> format is invalid");

  // Extract <ttl> and validate it.
  long long ttl;
  if (RedisModule_StringToLongLong(argv[3], &ttl) != REDISMODULE_OK)
    return RedisModule_ReplyWithError(
        ctx, "<ttl> must be a valid integer that represents seconds");
  if (ttl < 0)
    return RedisModule_ReplyWithError(
        ctx, "<ttl> must be a valid integer that represents seconds");

  // Parse the token.
  char tokenVersion[TOKEN_VERSION_STRLEN + 1];
  char sessionId[SESSION_ID_STRLEN + 1];
  char signature[SIGNATURE_STRLEN + 1];
  parseToken(token, tokenVersion, sessionId, signature);

  // Recreate the signature of the session id and compare with the signature
  // contained in the token.
  char signatureCheck[SIGNATURE_STRLEN + 1];
  signData((const unsigned char *)signKey, signKeyLen,
           (const unsigned char *)sessionId, SESSION_ID_STRLEN, signatureCheck);
  if (strncmp(signature, signatureCheck, SIGNATURE_STRLEN) != 0)
    return RedisModule_ReplyWithError(
        ctx, "the signature contained in <token> is invalid");

  // Check if the signature is the same stored in the session.
  RedisModuleString *sessionSignatureKeyStr =
      RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", sessionId);
  RedisModuleKey *redisKey = RedisModule_OpenKey(
      ctx, sessionSignatureKeyStr, REDISMODULE_READ | REDISMODULE_WRITE);
  if (RedisModule_KeyType(redisKey) != REDISMODULE_KEYTYPE_STRING) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the session id contained in <token> does not exist");
  }
  size_t signatureStoredLen;
  char *signatureStored =
      RedisModule_StringDMA(redisKey, &signatureStoredLen, REDISMODULE_READ);
  if (strncmp(signature, signatureStored, SIGNATURE_STRLEN) != 0) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the signature contained in <token> seems to be valid, but is "
             "different from the stored signature in the session");
  }

  // Set the TTL for the signature key.
  RedisModule_SetExpire(redisKey, ttl * 1000);
  RedisModule_CloseKey(redisKey);

  // Set the TTL for the payloads key if it exists.
  RedisModuleString *sessionPayloadsKeyStr =
      RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", sessionId);
  redisKey = RedisModule_OpenKey(ctx, sessionPayloadsKeyStr, REDISMODULE_WRITE);
  if (RedisModule_KeyType(redisKey) == REDISMODULE_KEYTYPE_HASH)
    RedisModule_SetExpire(redisKey, ttl * 1000);

  RedisModule_CloseKey(redisKey);

  RedisModule_ReplyWithSimpleString(ctx, "OK");
  return REDISMODULE_OK;
}


int PDelCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 4)
    return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  // Extract <sign_key> and validate it.
  size_t signKeyLen;
  const char *signKey = RedisModule_StringPtrLen(argv[1], &signKeyLen);
  if (signKeyLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<sign_key> must have at least one character");

  // Extract <token> and validate it.
  size_t tokenLen;
  const char *token = RedisModule_StringPtrLen(argv[2], &tokenLen);
  if (tokenLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<token> must have at least one character");
  else if (tokenLen != TOKEN_STRLEN)
    return RedisModule_ReplyWithError(ctx, "<token> format is invalid");

  // Parse the token.
  char tokenVersion[TOKEN_VERSION_STRLEN + 1];
  char sessionId[SESSION_ID_STRLEN + 1];
  char signature[SIGNATURE_STRLEN + 1];
  parseToken(token, tokenVersion, sessionId, signature);

  // Recreate the signature of the session id and compare with the signature
  // contained in the token.
  char signatureCheck[SIGNATURE_STRLEN + 1];
  signData((const unsigned char *)signKey, signKeyLen,
           (const unsigned char *)sessionId, SESSION_ID_STRLEN, signatureCheck);
  if (strncmp(signature, signatureCheck, SIGNATURE_STRLEN) != 0)
    return RedisModule_ReplyWithError(
        ctx, "the signature contained in <token> is invalid");

  // Check if the signature is the same stored in the session.
  RedisModuleString *sessionSignatureKeyStr =
      RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", sessionId);
  RedisModuleKey *redisKey = RedisModule_OpenKey(
      ctx, sessionSignatureKeyStr, REDISMODULE_READ | REDISMODULE_WRITE);
  if (RedisModule_KeyType(redisKey) != REDISMODULE_KEYTYPE_STRING) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the session id contained in <token> does not exist");
  }
  size_t signatureStoredLen;
  char *signatureStored =
      RedisModule_StringDMA(redisKey, &signatureStoredLen, REDISMODULE_READ);
  if (strncmp(signature, signatureStored, SIGNATURE_STRLEN) != 0) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the signature contained in <token> seems to be valid, but is "
             "different from the stored signature in the session");
  }

  RedisModule_CloseKey(redisKey);

  // Extract <payload_name> and validate it.
  const RedisModuleString *payloadName = argv[3];
  size_t payloadNameLen;
  RedisModule_StringPtrLen(payloadName, &payloadNameLen);
  if (payloadNameLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<payload_name> must have at least one character");
  else if (payloadNameLen > PAYLOAD_NAME_MAX_STRLEN) {
    char msg[128];
    sprintf(msg,
            "<payload_name> length exceeds the maximum value allowed of %zu",
            PAYLOAD_NAME_MAX_STRLEN);
    return RedisModule_ReplyWithError(ctx, msg);
  }

  // Delete the payload.
  RedisModuleString *sessionPayloadsKeyStr =
      RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", sessionId);
  redisKey = RedisModule_OpenKey(ctx, sessionPayloadsKeyStr, REDISMODULE_WRITE);
  if (RedisModule_KeyType(redisKey) != REDISMODULE_KEYTYPE_HASH) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the requested <payload_name> does not exist");
  }
  RedisModule_HashSet(redisKey, REDISMODULE_HASH_NONE, payloadName,
                      REDISMODULE_HASH_DELETE, NULL);
  RedisModule_CloseKey(redisKey);

    RedisModule_ReplyWithSimpleString(ctx, "OK");
    return REDISMODULE_OK;
}


int PGetCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 4)
    return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  // Extract <sign_key> and validate it.
  size_t signKeyLen;
  const char *signKey = RedisModule_StringPtrLen(argv[1], &signKeyLen);
  if (signKeyLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<sign_key> must have at least one character");

  // Extract <token> and validate it.
  size_t tokenLen;
  const char *token = RedisModule_StringPtrLen(argv[2], &tokenLen);
  if (tokenLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<token> must have at least one character");
  else if (tokenLen != TOKEN_STRLEN)
    return RedisModule_ReplyWithError(ctx, "<token> format is invalid");

  // Parse the token.
  char tokenVersion[TOKEN_VERSION_STRLEN + 1];
  char sessionId[SESSION_ID_STRLEN + 1];
  char signature[SIGNATURE_STRLEN + 1];
  parseToken(token, tokenVersion, sessionId, signature);

  // Recreate the signature of the session id and compare with the signature
  // contained in the token.
  char signatureCheck[SIGNATURE_STRLEN + 1];
  signData((const unsigned char *)signKey, signKeyLen,
           (const unsigned char *)sessionId, SESSION_ID_STRLEN, signatureCheck);
  if (strncmp(signature, signatureCheck, SIGNATURE_STRLEN) != 0)
    return RedisModule_ReplyWithError(
        ctx, "the signature contained in <token> is invalid");

  // Check if the signature is the same stored in the session.
  RedisModuleString *sessionSignatureKeyStr =
      RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", sessionId);
  RedisModuleKey *redisKey = RedisModule_OpenKey(
      ctx, sessionSignatureKeyStr, REDISMODULE_READ | REDISMODULE_WRITE);
  if (RedisModule_KeyType(redisKey) != REDISMODULE_KEYTYPE_STRING) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the session id contained in <token> does not exist");
  }
  size_t signatureStoredLen;
  char *signatureStored =
      RedisModule_StringDMA(redisKey, &signatureStoredLen, REDISMODULE_READ);
  if (strncmp(signature, signatureStored, SIGNATURE_STRLEN) != 0) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the signature contained in <token> seems to be valid, but is "
             "different from the stored signature in the session");
  }

  // Extract <payload_name> and validate it.
  const RedisModuleString *payloadName = argv[3];
  size_t payloadNameLen;
  RedisModule_StringPtrLen(payloadName, &payloadNameLen);
  if (payloadNameLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<payload_name> must have at least one character");
  else if (payloadNameLen > PAYLOAD_NAME_MAX_STRLEN) {
    char msg[128];
    sprintf(msg,
            "<payload_name> length exceeds the maximum value allowed of %zu",
            PAYLOAD_NAME_MAX_STRLEN);
    return RedisModule_ReplyWithError(ctx, msg);
  }

  // Get the payload.
  RedisModuleString *sessionPayloadsKeyStr =
      RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", sessionId);
  redisKey = RedisModule_OpenKey(ctx, sessionPayloadsKeyStr, REDISMODULE_READ);
  if (RedisModule_KeyType(redisKey) != REDISMODULE_KEYTYPE_HASH) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the requested <payload_name> does not exist");
  }
  RedisModuleString *payloadData;
  RedisModule_HashGet(redisKey, REDISMODULE_HASH_NONE, payloadName,
                      &payloadData, NULL);
  if (payloadData == NULL) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the requested <payload_name> does not exist");
  }
  RedisModule_CloseKey(redisKey);

  RedisModule_ReplyWithString(ctx, payloadData);
  return REDISMODULE_OK;
}


int PSetCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 5)
    return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  // Extract <sign_key> and validate it.
  size_t signKeyLen;
  const char *signKey = RedisModule_StringPtrLen(argv[1], &signKeyLen);
  if (signKeyLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<sign_key> must have at least one character");

  // Extract <token> and validate it.
  size_t tokenLen;
  const char *token = RedisModule_StringPtrLen(argv[2], &tokenLen);
  if (tokenLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<token> must have at least one character");
  else if (tokenLen != TOKEN_STRLEN)
    return RedisModule_ReplyWithError(ctx, "<token> format is invalid");

  // Parse the token.
  char tokenVersion[TOKEN_VERSION_STRLEN + 1];
  char sessionId[SESSION_ID_STRLEN + 1];
  char signature[SIGNATURE_STRLEN + 1];
  parseToken(token, tokenVersion, sessionId, signature);

  // Recreate the signature of the session id and compare with the signature
  // contained in the token.
  char signatureCheck[SIGNATURE_STRLEN + 1];
  signData((const unsigned char *)signKey, signKeyLen,
           (const unsigned char *)sessionId, SESSION_ID_STRLEN, signatureCheck);
  if (strncmp(signature, signatureCheck, SIGNATURE_STRLEN) != 0)
    return RedisModule_ReplyWithError(
        ctx, "the signature contained in <token> is invalid");

  // Check if the signature is the same stored in the session.
  RedisModuleString *sessionSignatureKeyStr =
      RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", sessionId);
  RedisModuleKey *redisKey = RedisModule_OpenKey(
      ctx, sessionSignatureKeyStr, REDISMODULE_READ | REDISMODULE_WRITE);
  if (RedisModule_KeyType(redisKey) != REDISMODULE_KEYTYPE_STRING) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the session id contained in <token> does not exist");
  }
  size_t signatureStoredLen;
  char *signatureStored =
      RedisModule_StringDMA(redisKey, &signatureStoredLen, REDISMODULE_READ);
  if (strncmp(signature, signatureStored, SIGNATURE_STRLEN) != 0) {
    RedisModule_CloseKey(redisKey);
    return RedisModule_ReplyWithError(
        ctx, "the signature contained in <token> seems to be valid, but is "
             "different from the stored signature in the session");
  }

  // Get the TTL of the session to assign it to the payload.
  mstime_t ttl = RedisModule_GetExpire(redisKey);

  RedisModule_CloseKey(redisKey);

  // Extract <payload_name> and validate it.
  const RedisModuleString *payloadName = argv[3];
  size_t payloadNameLen;
  RedisModule_StringPtrLen(payloadName, &payloadNameLen);
  if (payloadNameLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<payload_name> must have at least one character");
  else if (payloadNameLen > PAYLOAD_NAME_MAX_STRLEN) {
    char msg[128];
    sprintf(msg,
            "<payload_name> length exceeds the maximum value allowed of %zu",
            PAYLOAD_NAME_MAX_STRLEN);
    return RedisModule_ReplyWithError(ctx, msg);
  }

  // Extract <payload_data> and validate it.
  const RedisModuleString *payloadData = argv[4];
  size_t payloadDataLen;
  RedisModule_StringPtrLen(payloadData, &payloadDataLen);
  if (payloadDataLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<payload_data> must have at least one character");
  else if (payloadDataLen > PAYLOAD_DATA_MAX_STRLEN) {
    char msg[128];
    sprintf(msg,
            "<payload_data> length exceeds the maximum value allowed of %zu",
            PAYLOAD_DATA_MAX_STRLEN);
    return RedisModule_ReplyWithError(ctx, msg);
  }

  // Set the payload.
  RedisModuleString *sessionPayloadsKeyStr =
      RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", sessionId);
  redisKey = RedisModule_OpenKey(ctx, sessionPayloadsKeyStr, REDISMODULE_WRITE);
  RedisModule_HashSet(redisKey, REDISMODULE_HASH_NONE, payloadName, payloadData,
                      NULL);

  // Set the TTL.
  if (ttl > 0)
    RedisModule_SetExpire(redisKey, ttl);

  RedisModule_CloseKey(redisKey);

  RedisModule_ReplyWithSimpleString(ctx, "OK");
  return REDISMODULE_OK;
}


int StartCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 3)
    return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  // Extract <sign_key> and validate it.
  size_t signKeyLen;
  const char *signKey = RedisModule_StringPtrLen(argv[1], &signKeyLen);
  if (signKeyLen == 0)
    return RedisModule_ReplyWithError(
        ctx, "<sign_key> must have at least one character");

  // Extract <ttl> and validate it.
  long long ttl;
  if (RedisModule_StringToLongLong(argv[2], &ttl) != REDISMODULE_OK)
    return RedisModule_ReplyWithError(
        ctx, "<ttl> must be a valid integer that represents seconds");
  if (ttl < 0)
    return RedisModule_ReplyWithError(
        ctx, "<ttl> must be a valid integer that represents seconds");

  char sessionId[SESSION_ID_STRLEN + 1] = {0};
  RedisModuleString *sessionSignatureKeyStr;
  RedisModuleKey *redisKey;
  // A security measure to ensure no collisions will happen to existing session
  // IDs. Open a ticket and call me paranoid. You better like me being paranoid.
  while (1) {
    // Generate the session ID.
    generatePseudoRandomString(sessionId);
    sessionSignatureKeyStr = RedisModule_CreateStringPrintf(
        ctx, "sg-session:%s:signature", sessionId);

    // Verify if the session ID already exists.
    redisKey =
        RedisModule_OpenKey(ctx, sessionSignatureKeyStr, REDISMODULE_WRITE);
    if (RedisModule_KeyType(redisKey) == REDISMODULE_KEYTYPE_EMPTY)
      break;
  }

  char signature[SIGNATURE_STRLEN + 1];
  signData((const unsigned char *)signKey, signKeyLen,
           (const unsigned char *)sessionId, SESSION_ID_STRLEN, signature);
  RedisModule_StringSet(redisKey,
                        RedisModule_CreateStringPrintf(ctx, signature));

  // Set the session TTL.
  RedisModule_SetExpire(redisKey, ttl * 1000);

  RedisModule_CloseKey(redisKey);

  RedisModule_ReplyWithString(
      ctx, RedisModule_CreateStringPrintf(ctx, "%s.%s.%s", TOKEN_VERSION,
                                          sessionId, signature));
  return REDISMODULE_OK;
}



int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
    __attribute__((visibility("default")));
int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv,
                       int argc) {
  REDISMODULE_NOT_USED(argv);
  REDISMODULE_NOT_USED(argc);

  // Register the module.
  if (RedisModule_Init(ctx, "sessiongate", 1, REDISMODULE_APIVER_1) ==
      REDISMODULE_ERR)
    return REDISMODULE_ERR;

  // Register functions.
  RMUtil_RegisterWriteCmd(ctx, "sessiongate.start", StartCommand);
  RMUtil_RegisterWriteCmd(ctx, "sessiongate.end", EndCommand);
  RMUtil_RegisterWriteCmd(ctx, "sessiongate.pset", PSetCommand);
  RMUtil_RegisterWriteCmd(ctx, "sessiongate.pget", PGetCommand);
  RMUtil_RegisterWriteCmd(ctx, "sessiongate.pdel", PDelCommand);
  RMUtil_RegisterWriteCmd(ctx, "sessiongate.expire", ExpireCommand);

  return REDISMODULE_OK;
}

