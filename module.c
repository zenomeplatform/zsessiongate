#define SESSION_ID_DICTIONARY "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define SESSION_ID_DICTIONARY_STRLEN (size_t)62//strlen(SESSION_ID_DICTIONARY)
#define SESSION_ID_STRLEN (size_t)16 // SESSION_ID_DICTIONARY_STRLEN ^ 16 possible combinations.
#define SIGNATURE_STRLEN (size_t)64
#define TOKEN_VERSION_STRLEN (size_t)2//strlen(TOKEN_VERSION)
#define TOKEN_STRLEN (size_t)(TOKEN_VERSION_STRLEN + 1 + SESSION_ID_STRLEN + 1 + SIGNATURE_STRLEN)

#define PAYLOAD_NAME_MAX_STRLEN (size_t)200
#define PAYLOAD_DATA_MAX_STRLEN (size_t)1e6 * 8 // 8 MB.

#include <string.h>
#include "sodium.h"
#include "redismodule.h"

char* ERROR_INPUT_1 = "<sign_key> must have at least one character";
char* ERROR_INPUT_2 = "<token> format is invalid";
char* ERROR_INPUT_3 = "<payload_name> must have at least one character";
char* ERROR_INPUT_4 = "<payload_data> must have at least one character";
char* ERROR_INPUT_5 = "<payload_name> length exceeds the maximum value allowed";
char* ERROR_INPUT_6 = "<payload_data> length exceeds the maximum value allowed";
char* ERROR_INPUT_7 = "<ttl> must be a valid integer that represents seconds";

char* ERROR_SIG_1 = "the signature contained in <token> is invalid";
char* ERROR_SIG_2 = "the session id contained in <token> does not exist";
char* ERROR_SIG_3 = "the signature contained in <token> seems to be valid, but is different from the stored signature in the session";

typedef struct {
    char* tokenVersion;
    char* sessionId;
    char* signature;
} ParsedToken;


size_t ZSessionGate_Length(RedisModuleString* value) {
  size_t length = -1;
  RedisModule_StringPtrLen(value, &length);
  return length;
}

const char* ZSessionGate_ValidateLength(RedisModuleString* value, size_t min, const char* err_min, size_t max, const char* err_max) {
  size_t length = -1;
  RedisModule_StringPtrLen(value, &length);
  if (length < min) return err_min;
  if (length > max) return err_max;
  return NULL;
}

char* ZSessionGate_CString(RedisModuleString* value) {
  size_t length;
  const char* buffer = RedisModule_StringPtrLen(value, &length);
  char* string = RedisModule_Alloc(length + 1);
  for (int i = 0; i < length; i++) string[i] = buffer[i];
  string[length]= 0;
  return string;
}

long long ZSessionGate_UNumber(RedisModuleString* value) {
  long long ttl;
  if (RedisModule_StringToLongLong(value, &ttl) == REDISMODULE_OK)
    return ttl;
  return -1;
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

ParsedToken parse(RedisModuleString* value) {
  char* token = ZSessionGate_CString(value);

  char* tokenVersion = RedisModule_Strdup(token);
  tokenVersion[TOKEN_VERSION_STRLEN] = '\0';
  char* sessionId = tokenVersion + TOKEN_VERSION_STRLEN + 1;
  sessionId[SESSION_ID_STRLEN] = '\0';
  char* signature = sessionId + SESSION_ID_STRLEN + 1;
  return (ParsedToken) { tokenVersion, sessionId, signature };
}

char* ZSessionGate_CheckSignature(RedisModuleCtx *ctx, char* signKey, ParsedToken parsed) {
  char signatureCheck[SIGNATURE_STRLEN + 1];
  signData(signKey, parsed.sessionId, signatureCheck);
  int code = strncmp(parsed.signature, signatureCheck, SIGNATURE_STRLEN);
  if (code != 0) return ERROR_SIG_1;

  RedisModuleString *signatureKeyStr = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", parsed.sessionId);
  RedisModuleKey *signatureKey = RedisModule_OpenKey(ctx, signatureKeyStr, REDISMODULE_READ);
  if (RedisModule_KeyType(signatureKey) != REDISMODULE_KEYTYPE_STRING) return ERROR_SIG_2;
  
  size_t signatureStoredLen;
  char *signatureStored = RedisModule_StringDMA(signatureKey, &signatureStoredLen, REDISMODULE_READ);
  if (!signatureStored || signatureStoredLen!= SIGNATURE_STRLEN) return ERROR_SIG_2;

  code = strncmp(parsed.signature, signatureStored, SIGNATURE_STRLEN);
  if (code != 0) return ERROR_SIG_3;

  return NULL;
}

void ZSessionGate_DeleteRecord(RedisModuleCtx *ctx, ParsedToken parsed, const char *subname) {
    RedisModuleString *str = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:%s", parsed.sessionId, subname);
    RedisModuleKey *key = RedisModule_OpenKey(ctx, str, REDISMODULE_WRITE);
    if (RedisModule_KeyType(key) == REDISMODULE_KEYTYPE_EMPTY) return;
    RedisModule_DeleteKey(key);
}

void ZSessionGate_SetRecordTTL(RedisModuleCtx *ctx, ParsedToken parsed, const char *subname, long long ttl) {
    RedisModuleString *str = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:%s", parsed.sessionId, subname);
    RedisModuleKey *key = RedisModule_OpenKey(ctx, str, REDISMODULE_WRITE);
    if (RedisModule_KeyType(key) == REDISMODULE_KEYTYPE_EMPTY) return;
    RedisModule_SetExpire(key, ttl * 1000);
}

RedisModuleString* ZSessionGate_GetRecordProperty(RedisModuleCtx *ctx, ParsedToken parsed, RedisModuleString* property) {
    RedisModuleString *str = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", parsed.sessionId);
    RedisModuleKey *key = RedisModule_OpenKey(ctx, str, REDISMODULE_READ);
    if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_HASH) return NULL;
    RedisModuleString *payloadData = NULL;
    RedisModule_HashGet(key, REDISMODULE_HASH_NONE, property, &payloadData, NULL);
    return payloadData;
}

long long ZSessionGate_ReadTTL(RedisModuleCtx *ctx, ParsedToken parsed) {
    RedisModuleString *str = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", parsed.sessionId);
    RedisModuleKey* key = RedisModule_OpenKey(ctx, str, REDISMODULE_READ);
    return RedisModule_GetExpire(key);
}

void ZSessionGate_SetHashPayload(RedisModuleCtx *ctx, ParsedToken parsed, RedisModuleString *name, RedisModuleString *value, long long ttl) {
    RedisModuleString *str = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", parsed.sessionId);
    RedisModuleKey* key = RedisModule_OpenKey(ctx, str, REDISMODULE_WRITE);
    RedisModule_HashSet(key, REDISMODULE_HASH_NONE, name, value, NULL);
    if (ttl > 0) RedisModule_SetExpire(key, ttl);
}

int EndCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 3) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);
  const char* error = NULL;

  if (ZSessionGate_Length(argv[1]) == 0) return RedisModule_ReplyWithError(ctx, ERROR_INPUT_1);

  if (error == NULL) error = ZSessionGate_ValidateLength(argv[2], TOKEN_STRLEN , ERROR_INPUT_2, TOKEN_STRLEN, ERROR_INPUT_2);
  if (error) return RedisModule_ReplyWithError(ctx, error);

  ParsedToken parsed = parse(argv[2]);

  error = ZSessionGate_CheckSignature(ctx, ZSessionGate_CString(argv[1]), parsed);
  if (error) return RedisModule_ReplyWithError(ctx, error);

  ZSessionGate_DeleteRecord(ctx, parsed, "signature");
  ZSessionGate_DeleteRecord(ctx, parsed, "payloads");

  return RedisModule_ReplyWithSimpleString(ctx, "OK");
}


int ExpireCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 4) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);
  const char* error = NULL;

  if (ZSessionGate_Length(argv[1]) == 0) 
    return RedisModule_ReplyWithError(ctx, ERROR_INPUT_1);

  if (error == NULL) error = ZSessionGate_ValidateLength(argv[2], TOKEN_STRLEN , ERROR_INPUT_2, TOKEN_STRLEN, ERROR_INPUT_2);
  if (error) return RedisModule_ReplyWithError(ctx, error);

  long long ttl = ZSessionGate_UNumber(argv[3]);
  if (ttl < 0) return RedisModule_ReplyWithError(ctx, ERROR_INPUT_7);

  ParsedToken parsed = parse(argv[2]);

  error = ZSessionGate_CheckSignature(ctx,  ZSessionGate_CString(argv[1]), parsed);
  if (error) return RedisModule_ReplyWithError(ctx, error);

  ZSessionGate_SetRecordTTL(ctx, parsed, "signature", ttl);
  ZSessionGate_SetRecordTTL(ctx, parsed, "payloads", ttl);

  return RedisModule_ReplyWithSimpleString(ctx, "OK");
}


int PDelCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 4) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);
  const char* error = NULL;

  if (ZSessionGate_Length(argv[1]) == 0)
    return RedisModule_ReplyWithError(ctx, ERROR_INPUT_1);
    
  if (error == NULL) error = ZSessionGate_ValidateLength(argv[2], TOKEN_STRLEN , ERROR_INPUT_2, TOKEN_STRLEN, ERROR_INPUT_2);
  if (error == NULL) error = ZSessionGate_ValidateLength(argv[3],  1 , ERROR_INPUT_3, PAYLOAD_NAME_MAX_STRLEN, ERROR_INPUT_5);

  if (error) return RedisModule_ReplyWithError(ctx, error);
  
  ParsedToken parsed = parse(argv[2]);
  error = ZSessionGate_CheckSignature(ctx, ZSessionGate_CString(argv[1]), parsed);

  if (error) return RedisModule_ReplyWithError(ctx, error);

  // Delete the payload.
  RedisModuleString *sessionPayloadsKeyStr = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:payloads", parsed.sessionId);
  RedisModuleKey* redisKey = RedisModule_OpenKey(ctx, sessionPayloadsKeyStr, REDISMODULE_WRITE);

  if (RedisModule_KeyType(redisKey) != REDISMODULE_KEYTYPE_HASH) {
    return RedisModule_ReplyWithError(ctx, "the requested <payload_name> does not exist");
  }
  RedisModule_HashSet(redisKey, REDISMODULE_HASH_NONE, argv[3], REDISMODULE_HASH_DELETE, NULL);

  return RedisModule_ReplyWithSimpleString(ctx, "OK");
}


int PGetCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 4) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);
  const char* error = NULL;

  if (ZSessionGate_Length(argv[1]) == 0) return RedisModule_ReplyWithError(ctx, ERROR_INPUT_1);
    
  if (error == NULL) error = ZSessionGate_ValidateLength(argv[2], TOKEN_STRLEN , ERROR_INPUT_2, TOKEN_STRLEN, ERROR_INPUT_2);
  if (error == NULL) error = ZSessionGate_ValidateLength(argv[3],  1 , ERROR_INPUT_3, PAYLOAD_NAME_MAX_STRLEN, ERROR_INPUT_5);

  if (error) return RedisModule_ReplyWithError(ctx, error);

  ParsedToken parsed = parse(argv[2]);

  error = ZSessionGate_CheckSignature(ctx, ZSessionGate_CString(argv[1]), parsed);
  if (error) return RedisModule_ReplyWithError(ctx, error);

  RedisModuleString *data = ZSessionGate_GetRecordProperty(ctx, parsed, argv[3]);
  return RedisModule_ReplyWithString(ctx, data);
}


int PSetCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 5) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);
  const char* error = NULL;

  if (ZSessionGate_Length(argv[1]) == 0) return RedisModule_ReplyWithError(ctx, ERROR_INPUT_1);

  if (error == NULL) error = ZSessionGate_ValidateLength(argv[2], TOKEN_STRLEN , ERROR_INPUT_2, TOKEN_STRLEN, ERROR_INPUT_2);
  if (error == NULL) error = ZSessionGate_ValidateLength(argv[3], 1 , ERROR_INPUT_3, PAYLOAD_NAME_MAX_STRLEN, ERROR_INPUT_5);
  if (error == NULL) error = ZSessionGate_ValidateLength(argv[4], 1 , ERROR_INPUT_4, PAYLOAD_DATA_MAX_STRLEN, ERROR_INPUT_6);

  if (error) return RedisModule_ReplyWithError(ctx, error);

  ParsedToken parsed = parse(argv[2]);

  error = ZSessionGate_CheckSignature(ctx, ZSessionGate_CString(argv[1]), parsed);
  if (error) return RedisModule_ReplyWithError(ctx, error);

  ZSessionGate_SetHashPayload(ctx, parsed, argv[3], argv[4], ZSessionGate_ReadTTL(ctx, parsed));

  return RedisModule_ReplyWithSimpleString(ctx, "OK");
}


int StartCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 3) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);
  //const char* error = NULL;

  if (ZSessionGate_Length(argv[1]) == 0) return RedisModule_ReplyWithError(ctx, ERROR_INPUT_1);

  long long ttl = ZSessionGate_UNumber(argv[2]);
  if (ttl < 0) return RedisModule_ReplyWithError(ctx, ERROR_INPUT_7);

  char sessionId[SESSION_ID_STRLEN + 1];
  char signature[SIGNATURE_STRLEN + 1];

  while (1) {
    generatePseudoRandomString(sessionId); // Generate the session ID.
    RedisModuleString *str = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", sessionId);
    // Verify if the session ID already exists.
    RedisModuleKey *key = RedisModule_OpenKey(ctx, str, REDISMODULE_READ);
    if (RedisModule_KeyType(key) == REDISMODULE_KEYTYPE_EMPTY) break;
  }

  signData(ZSessionGate_CString(argv[1]), sessionId, signature);

  {
      RedisModuleString *str = RedisModule_CreateStringPrintf(ctx, "sg-session:%s:signature", sessionId);
      RedisModuleKey *key = RedisModule_OpenKey(ctx, str, REDISMODULE_WRITE);
      RedisModule_StringSet(key, RedisModule_CreateString(ctx, signature, SIGNATURE_STRLEN));
      RedisModule_SetExpire(key, ttl * 1000);
  }

  RedisModuleString *redisReply = RedisModule_CreateStringPrintf(ctx, "v1.%s.%s", sessionId, signature); 
  return RedisModule_ReplyWithString(ctx, redisReply);
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
    __attribute__((visibility("default")));

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  REDISMODULE_NOT_USED(argv);
  REDISMODULE_NOT_USED(argc);

  int code = RedisModule_Init(ctx, "sessiongate", 1, REDISMODULE_APIVER_1);

  if (code == REDISMODULE_OK) code = RedisModule_CreateCommand(ctx, "sessiongate.start",  StartCommand,  "write", 1, 1, 1);  
  if (code == REDISMODULE_OK) code = RedisModule_CreateCommand(ctx, "sessiongate.end",    EndCommand,    "write", 1, 1, 1);
  if (code == REDISMODULE_OK) code = RedisModule_CreateCommand(ctx, "sessiongate.pset",   PSetCommand,   "write", 1, 1, 1);  
  if (code == REDISMODULE_OK) code = RedisModule_CreateCommand(ctx, "sessiongate.pget",   PGetCommand,   "write", 1, 1, 1);
  if (code == REDISMODULE_OK) code = RedisModule_CreateCommand(ctx, "sessiongate.pdel",   PDelCommand,   "write", 1, 1, 1);  
  if (code == REDISMODULE_OK) code = RedisModule_CreateCommand(ctx, "sessiongate.expire", ExpireCommand, "write", 1, 1, 1);

  return code;
}

