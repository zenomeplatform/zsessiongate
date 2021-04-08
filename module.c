#define SESSION_ID_DICTIONARY "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define SESSION_ID_DICTIONARY_STRLEN (size_t)62//strlen(SESSION_ID_DICTIONARY)
#define SESSION_ID_STRLEN (size_t)16 // SESSION_ID_DICTIONARY_STRLEN ^ 16 possible combinations.

// The signature is encoded as hex string.
// Each byte uses 2 characters. 256 bits (SHA-256) = 32 bytes. 32 bytes * 2 = 64 bytes.
#define SIGNATURE_STRLEN (size_t)64

// The token version is used for future token compatibilities.
#define TOKEN_VERSION_STRLEN (size_t)2//strlen(TOKEN_VERSION)
// TOKEN_VERSION_STRLEN + 1 dot + SESSION_ID_STRLEN + 1 dot + SIGNATURE_STRLEN.
#define TOKEN_STRLEN (size_t)(TOKEN_VERSION_STRLEN + 1 + SESSION_ID_STRLEN + 1 + SIGNATURE_STRLEN)

#define PAYLOAD_NAME_MAX_STRLEN (size_t)200
#define PAYLOAD_DATA_MAX_STRLEN (size_t)1e6 * 8 // 8 MB.

#include <string.h>

#include "sodium.h"
#include "redismodule.h"
#include "rmutil/util.h"
#include "rmutil/logging.h"

typedef struct {
    char* tokenVersion;
    char* sessionId;
    char* signature;
} ParsedToken;

char* RedisModule_CString(RedisModuleString* value) {
  size_t length;
  const char* buffer = RedisModule_StringPtrLen(value, &length);
  char* string = RedisModule_Alloc(length + 1);
  for (int i = 0; i < length; i++) string[i] = buffer[i];
  string[length]= 0;
  return string;
}

long long RedisModule_UNumber(RedisModuleString* value) {
  long long ttl;
  int code = RedisModule_StringToLongLong(value, &ttl);
  if (code == REDISMODULE_OK) return ttl;
  return -1;
}

RedisModuleKey *RedisSessions_GetStoredSignatureKey(RedisModuleCtx *ctx, const char* id) {
  RedisModuleString *sessionSignatureKeyStr = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", id);
  RedisModuleKey *redisKey = RedisModule_OpenKey(ctx, sessionSignatureKeyStr, REDISMODULE_READ | REDISMODULE_WRITE);
  if (RedisModule_KeyType(redisKey) == REDISMODULE_KEYTYPE_STRING) return redisKey;
  return NULL;
}


void generatePseudoRandomString(char *generatedStr) {
  uint8_t buf[SESSION_ID_STRLEN];
  randombytes_buf(buf, SESSION_ID_STRLEN);
  for (uint16_t i = 0; i < SESSION_ID_STRLEN; i++)
    generatedStr[i] = SESSION_ID_DICTIONARY[buf[i] % SESSION_ID_DICTIONARY_STRLEN];
  generatedStr[SESSION_ID_STRLEN] = '\0';
}

void signData(const char *key, const char *data, char *signature) {
  unsigned char signatureHash[crypto_auth_hmacsha256_BYTES];
  crypto_auth_hmacsha256_state state;
  crypto_auth_hmacsha256_init(&state, (const unsigned char *)key, strlen(key));
  crypto_auth_hmacsha256_update(&state, (const unsigned char *)data, strlen(data));
  crypto_auth_hmacsha256_final(&state, signatureHash);
  sodium_bin2hex(signature, SIGNATURE_STRLEN + 1, signatureHash, 32); // 32 bytes = 256 bits.
}

int doSignatureCheck(const char *key, const char *id, char *signature) {
  char signatureCheck[SIGNATURE_STRLEN + 1];
  signData(key, id, signatureCheck);
  return 0 == strncmp(signature, signatureCheck, SIGNATURE_STRLEN);
}

ParsedToken parse(const char *token) {
  char* tokenVersion = RedisModule_Strdup(token);
  tokenVersion[TOKEN_VERSION_STRLEN] = '\0';
  char* sessionId = tokenVersion + TOKEN_VERSION_STRLEN + 1;
  sessionId[SESSION_ID_STRLEN] = '\0';
  char* signature = sessionId + SESSION_ID_STRLEN + 1;
  return (ParsedToken) { tokenVersion, sessionId, signature };
}

int RedisModule_CheckSignature(RedisModuleCtx *ctx, char* signKey, ParsedToken parsed) {
  char signatureCheck[SIGNATURE_STRLEN + 1];
  signData(signKey, parsed.sessionId, signatureCheck);
  int code = strncmp(parsed.signature, signatureCheck, SIGNATURE_STRLEN);
  if (code != 0) return -1;

  RedisModuleString *signatureKeyStr = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", parsed.sessionId);
  RedisModuleKey *signatureKey = RedisModule_OpenKey(ctx, signatureKeyStr, REDISMODULE_READ);
  if (RedisModule_KeyType(signatureKey) != REDISMODULE_KEYTYPE_STRING) return -2;
  
  size_t signatureStoredLen;
  char *signatureStored = RedisModule_StringDMA(signatureKey, &signatureStoredLen, REDISMODULE_READ);
  if (!signatureStored || signatureStoredLen!= SIGNATURE_STRLEN) return -2;

  code = strncmp(parsed.signature, signatureStored, SIGNATURE_STRLEN);
  if (code != 0) return -3;

  return 0;
}

int EndCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 3) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  char *signKey = RedisModule_CString(argv[1]);
  char *token   = RedisModule_CString(argv[2]);

  if (strlen(signKey) == 0)          return RedisModule_ReplyWithError(ctx, "<sign_key> must have at least one character");
  if (strlen(token) != TOKEN_STRLEN) return RedisModule_ReplyWithError(ctx, "<token> format is invalid");

  ParsedToken parsed = parse(token);

  switch (RedisModule_CheckSignature(ctx, signKey, parsed)) {
    case -1: return RedisModule_ReplyWithError(ctx, "the signature contained in <token> is invalid");
    case -2: return RedisModule_ReplyWithError(ctx, "the session id contained in <token> does not exist");
    case -3: return RedisModule_ReplyWithError(ctx, "the signature contained in <token> seems to be valid, but is different from the stored signature in the session");
  }

  {
      RedisModuleString *str = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", parsed.sessionId);
      RedisModuleKey *key = RedisModule_OpenKey(ctx, str, REDISMODULE_WRITE);
      if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_EMPTY) RedisModule_DeleteKey(key);
  }

  {
      RedisModuleString *str = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", parsed.sessionId);
      RedisModuleKey *key = RedisModule_OpenKey(ctx, str, REDISMODULE_WRITE);
      if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_EMPTY) RedisModule_DeleteKey(key);
  }

  return RedisModule_ReplyWithSimpleString(ctx, "OK");
}


int ExpireCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 4) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  char *signKey = RedisModule_CString(argv[1]);
  char *token   = RedisModule_CString(argv[2]);
  long long ttl = RedisModule_UNumber(argv[3]);

  if (strlen(signKey) == 0)            return RedisModule_ReplyWithError(ctx, "<sign_key> must have at least one character");
  if (strlen(token) != TOKEN_STRLEN)   return RedisModule_ReplyWithError(ctx, "<token> format is invalid");
  if (ttl < 0)                         return RedisModule_ReplyWithError(ctx, "<ttl> must be a valid integer that represents seconds");

  ParsedToken parsed = parse(token);
  
  if (!doSignatureCheck(signKey, parsed.sessionId, parsed.signature))
    return RedisModule_ReplyWithError(ctx, "the signature contained in <token> is invalid");
  RedisModuleKey *redisKey = RedisSessions_GetStoredSignatureKey(ctx, parsed.sessionId);
  if (!redisKey) return RedisModule_ReplyWithError(ctx, "the session id contained in <token> does not exist");
  
  size_t signatureStoredLen;
  char *signatureStored = RedisModule_StringDMA(redisKey, &signatureStoredLen, REDISMODULE_READ);
  if (strncmp(parsed.signature, signatureStored, SIGNATURE_STRLEN) != 0) {
    return RedisModule_ReplyWithError(ctx, "the signature contained in <token> seems to be valid, but is different from the stored signature in the session");
  }

  // Set the TTL for the signature key.
  RedisModule_SetExpire(redisKey, ttl * 1000);

  // Set the TTL for the payloads key if it exists.
  RedisModuleString *sessionPayloadsKeyStr = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", parsed.sessionId);
  redisKey = RedisModule_OpenKey(ctx, sessionPayloadsKeyStr, REDISMODULE_WRITE);
  if (RedisModule_KeyType(redisKey) == REDISMODULE_KEYTYPE_HASH)
    RedisModule_SetExpire(redisKey, ttl * 1000);


  return RedisModule_ReplyWithSimpleString(ctx, "OK");
}


int PDelCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 4) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  char *signKey = RedisModule_CString(argv[1]);
  char *token   = RedisModule_CString(argv[2]);
  char *name    = RedisModule_CString(argv[3]);

  if (strlen(signKey) == 0)                   return RedisModule_ReplyWithError(ctx, "<sign_key> must have at least one character");
  if (strlen(token) != TOKEN_STRLEN)          return RedisModule_ReplyWithError(ctx, "<token> format is invalid");
  if (strlen(name) == 0)                      return RedisModule_ReplyWithError(ctx, "<payload_name> must have at least one character");
  if (strlen(name) > PAYLOAD_NAME_MAX_STRLEN) return RedisModule_ReplyWithError(ctx, "<payload_name> length exceeds the maximum value allowed");
  
  ParsedToken parsed = parse(token);

  // Recreate the signature of the session id and compare with the signature
  // contained in the token.
  if (!doSignatureCheck(signKey, parsed.sessionId, parsed.signature))
    return RedisModule_ReplyWithError(ctx, "the signature contained in <token> is invalid");

  // Check if the signature is the same stored in the session.
  RedisModuleKey *redisKey = RedisSessions_GetStoredSignatureKey(ctx, parsed.sessionId);
  if (!redisKey) return RedisModule_ReplyWithError(ctx, "the session id contained in <token> does not exist");
  
  size_t signatureStoredLen;
  char *signatureStored = RedisModule_StringDMA(redisKey, &signatureStoredLen, REDISMODULE_READ);
  if (strncmp(parsed.signature, signatureStored, SIGNATURE_STRLEN) != 0) {
    return RedisModule_ReplyWithError(ctx, "the signature contained in <token> seems to be valid, but is different from the stored signature in the session");
  }
  // Delete the payload.
  RedisModuleString *sessionPayloadsKeyStr = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", parsed.sessionId);
  redisKey = RedisModule_OpenKey(ctx, sessionPayloadsKeyStr, REDISMODULE_WRITE);
  if (RedisModule_KeyType(redisKey) != REDISMODULE_KEYTYPE_HASH) {
    return RedisModule_ReplyWithError(ctx, "the requested <payload_name> does not exist");
  }
  RedisModule_HashSet(redisKey, REDISMODULE_HASH_NONE, argv[3], REDISMODULE_HASH_DELETE, NULL);

  return RedisModule_ReplyWithSimpleString(ctx, "OK");
}


int PGetCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 4) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  char *signKey = RedisModule_CString(argv[1]);
  char *token   = RedisModule_CString(argv[2]);
  char *name    = RedisModule_CString(argv[3]);

  if (strlen(signKey) == 0)                   return RedisModule_ReplyWithError(ctx, "<sign_key> must have at least one character");
  if (strlen(token) != TOKEN_STRLEN)          return RedisModule_ReplyWithError(ctx, "<token> format is invalid");
  if (strlen(name) == 0)                      return RedisModule_ReplyWithError(ctx, "<payload_name> must have at least one character");
  if (strlen(name) > PAYLOAD_NAME_MAX_STRLEN) return RedisModule_ReplyWithError(ctx, "<payload_name> length exceeds the maximum value allowed");

  ParsedToken parsed = parse(token);

  // Recreate the signature of the session id and compare with the signature
  // contained in the token.
  if (!doSignatureCheck(signKey, parsed.sessionId, parsed.signature))
    return RedisModule_ReplyWithError(ctx, "the signature contained in <token> is invalid");

  // Check if the signature is the same stored in the session.
  RedisModuleKey *redisKey = RedisSessions_GetStoredSignatureKey(ctx, parsed.sessionId);
  if (!redisKey) return RedisModule_ReplyWithError(ctx, "the session id contained in <token> does not exist");
  
  size_t signatureStoredLen;
  char *signatureStored = RedisModule_StringDMA(redisKey, &signatureStoredLen, REDISMODULE_READ);
  if (strncmp(parsed.signature, signatureStored, SIGNATURE_STRLEN) != 0) {
    return RedisModule_ReplyWithError(ctx, "the signature contained in <token> seems to be valid, but is different from the stored signature in the session");
  }

  // Get the payload.
  RedisModuleString *sessionPayloadsKeyStr = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", parsed.sessionId);
  redisKey = RedisModule_OpenKey(ctx, sessionPayloadsKeyStr, REDISMODULE_READ);
  RedisModuleString *payloadData = NULL;
  if (RedisModule_KeyType(redisKey) == REDISMODULE_KEYTYPE_HASH) {
    RedisModule_HashGet(redisKey, REDISMODULE_HASH_NONE, argv[3], &payloadData, NULL);
  }

  if (payloadData == NULL) {
    return RedisModule_ReplyWithError(ctx, "the requested <payload_name> does not exist");
  } else {
    return RedisModule_ReplyWithString(ctx, payloadData);
  }
}


int PSetCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 5) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  char *signKey = RedisModule_CString(argv[1]);
  char *token = RedisModule_CString(argv[2]);
  char *name = RedisModule_CString(argv[3]);
  char *data = RedisModule_CString(argv[4]);

  if (strlen(signKey) == 0)                   return RedisModule_ReplyWithError(ctx, "<sign_key> must have at least one character");
  if (strlen(token) != TOKEN_STRLEN)          return RedisModule_ReplyWithError(ctx, "<token> format is invalid");
  if (strlen(name) == 0)                      return RedisModule_ReplyWithError(ctx, "<payload_name> must have at least one character");
  if (strlen(data) == 0)                      return RedisModule_ReplyWithError(ctx, "<payload_data> must have at least one character");
  if (strlen(name) > PAYLOAD_NAME_MAX_STRLEN) return RedisModule_ReplyWithError(ctx, "<payload_name> length exceeds the maximum value allowed");
  if (strlen(data) > PAYLOAD_DATA_MAX_STRLEN) return RedisModule_ReplyWithError(ctx, "<payload_data> length exceeds the maximum value allowed");

  ParsedToken parsed = parse(token);

  // Recreate the signature of the session id and compare with the signature
  // contained in the token.
  if (!doSignatureCheck(signKey, parsed.sessionId, parsed.signature))
    return RedisModule_ReplyWithError(ctx, "the signature contained in <token> is invalid");

  // Check if the signature is the same stored in the session.
  RedisModuleKey *redisKey = RedisSessions_GetStoredSignatureKey(ctx, parsed.sessionId);
  if (!redisKey) return RedisModule_ReplyWithError(ctx, "the session id contained in <token> does not exist");
  

  size_t signatureStoredLen;
  char *signatureStored = RedisModule_StringDMA(redisKey, &signatureStoredLen, REDISMODULE_READ);
  if (strncmp(parsed.signature, signatureStored, SIGNATURE_STRLEN) != 0) {
    return RedisModule_ReplyWithError(ctx, "the signature contained in <token> seems to be valid, but is different from the stored signature in the session");
  }

  // Get the TTL of the session to assign it to the payload.
  mstime_t ttl = RedisModule_GetExpire(redisKey);

  // Set the payload.
  RedisModuleString *sessionPayloadsKeyStr = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", parsed.sessionId);
  redisKey = RedisModule_OpenKey(ctx, sessionPayloadsKeyStr, REDISMODULE_WRITE);
  RedisModule_HashSet(redisKey, REDISMODULE_HASH_NONE, argv[3], argv[4], NULL);
  if (ttl > 0) RedisModule_SetExpire(redisKey, ttl);

  return RedisModule_ReplyWithSimpleString(ctx, "OK");
}


int StartCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 3) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  char *signKey = RedisModule_CString(argv[1]);
  long long ttl = RedisModule_UNumber(argv[2]);

  if (strlen(signKey) == 0) return RedisModule_ReplyWithError(ctx, "<sign_key> must have at least one character");
  if (ttl < 0)              return RedisModule_ReplyWithError(ctx, "<ttl> must be a valid integer that represents seconds");

  RedisModuleKey *redisKey;
  char sessionId[SESSION_ID_STRLEN + 1];
  char signature[SIGNATURE_STRLEN + 1];

  while (1) {
    RedisModuleString *sessionSignatureKeyStr;
    generatePseudoRandomString(sessionId); // Generate the session ID.
    sessionSignatureKeyStr = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", sessionId);
    // Verify if the session ID already exists.
    redisKey = RedisModule_OpenKey(ctx, sessionSignatureKeyStr, REDISMODULE_WRITE);
    if (RedisModule_KeyType(redisKey) == REDISMODULE_KEYTYPE_EMPTY) break;
  }

  signData(signKey, sessionId, signature);

  RedisModule_StringSet(redisKey, RedisModule_CreateString(ctx, signature, SIGNATURE_STRLEN));
  RedisModule_SetExpire(redisKey, ttl * 1000);

  RedisModuleString *redisReply = RedisModule_CreateStringPrintf(ctx, "v1.%s.%s", sessionId, signature); 
  return RedisModule_ReplyWithString(ctx, redisReply);
}



int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
    __attribute__((visibility("default")));

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  REDISMODULE_NOT_USED(argv);
  REDISMODULE_NOT_USED(argc);

  int code = RedisModule_Init(ctx, "sessiongate", 1, REDISMODULE_APIVER_1);

  if (code == REDISMODULE_OK) {
    RMUtil_RegisterWriteCmd(ctx, "sessiongate.start", StartCommand);
    RMUtil_RegisterWriteCmd(ctx, "sessiongate.end", EndCommand);
    RMUtil_RegisterWriteCmd(ctx, "sessiongate.pset", PSetCommand);
    RMUtil_RegisterWriteCmd(ctx, "sessiongate.pget", PGetCommand);
    RMUtil_RegisterWriteCmd(ctx, "sessiongate.pdel", PDelCommand);
    RMUtil_RegisterWriteCmd(ctx, "sessiongate.expire", ExpireCommand);
  }

  return code;
}

