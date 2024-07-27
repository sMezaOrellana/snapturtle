#ifndef Shared_h
#define Shared_h
#include <Appkit/AppKit.h>
#include <CommonCrypto/CommonDigest.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#include <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <stdint.h>

void init_date_formater(void);
uint64_t MachTimeToSeconds(uint64_t machTime);
NSString *_Nonnull SHA1ForFileAtPath(NSString *_Nonnull filePath);
typedef struct {
  const NSString *_Nullable name;
  int value;
} CSFlag;

#define CSFLAG(flag)                                                           \
  { @ #flag, flag }

NSString *_Nonnull codesigning_flags_str(const uint32_t codesigning_flags);
NSString *_Nonnull esstring_to_nsstring(
    const es_string_token_t es_string_token);
const NSString *_Nonnull event_type_str(const es_event_type_t event_type);
NSString *_Nonnull events_str(size_t count,
                              const es_event_type_t *_Nonnull events);
// On macOS Big Sur 11, Apple have deprecated es_copy_message in favour of
// es_retain_message
es_message_t *_Nonnull copy_message(const es_message_t *_Nonnull msg);
// On macOS Big Sur 11, Apple have deprecated es_free_message in favour of
// es_release_message
void free_message(es_message_t *_Nonnull msg);
#pragma mark Helpers - Misc

NSString *_Nonnull fdtype_str(const uint32_t fdtype);
bool is_system_file(const NSString *_Nonnull path);
bool is_plain_text_file(const NSString *_Nonnull path);
char *_Nonnull filetype_str(const mode_t st_mode);
#define BOOL_VALUE(x) x ? "Yes" : "No"

// #pragma mark - Endpoint Secuirty Demo
#endif
