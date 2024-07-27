#include "shared.h"
NSDateFormatter *_Nullable g_date_formater = nil;

void init_date_formater(void) {
  // Display dates in RFC 3339 date and time format:
  // https://www.ietf.org/rfc/rfc3339.txt
  g_date_formater = [NSDateFormatter new];
  g_date_formater.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
  g_date_formater.dateFormat = @"yyyy-MM-dd'T'HH:mm:ssZZZZZ";
  g_date_formater.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
}

NSString *formatted_date_str(__darwin_time_t secs_since_1970) {
  NSDate *date = [NSDate dateWithTimeIntervalSince1970:secs_since_1970];
  return [g_date_formater stringFromDate:date];
}
uint64_t MachTimeToNanoseconds(uint64_t machTime) {
  uint64_t nanoseconds = 0;
  static mach_timebase_info_data_t sTimebase;
  if (sTimebase.denom == 0)
    (void)mach_timebase_info(&sTimebase);

  nanoseconds = ((machTime * sTimebase.numer) / sTimebase.denom);

  return nanoseconds;
}

uint64_t MachTimeToSeconds(uint64_t machTime) {
  return MachTimeToNanoseconds(machTime) / NSEC_PER_SEC;
}

NSString *_Nonnull SHA1ForFileAtPath(NSString *filePath) {
  NSFileManager *fileManager = [NSFileManager defaultManager];
  if (![fileManager fileExistsAtPath:filePath]) {
    NSLog(@"File does not exist at path: %@", filePath);
    return @"";
  }

  NSData *fileData = [NSData dataWithContentsOfFile:filePath];
  if (!fileData) {
    NSLog(@"Failed to read file data from path: %@", filePath);
    return @"";
  }

  unsigned char hash[CC_SHA1_DIGEST_LENGTH];
  if (CC_SHA1([fileData bytes], (CC_LONG)[fileData length], hash)) {
    NSMutableString *hashString =
        [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
      [hashString appendFormat:@"%02x", hash[i]];
    }
    return [hashString copy];
  } else {
    NSLog(@"Failed to calculate SHA1 hash for file at path: %@", filePath);
    return @"";
  }
}

// Code signing flags defined in cs_blobs.h
const CSFlag g_csFlags[] = {CSFLAG(CS_VALID),
                            CSFLAG(CS_ADHOC),
                            CSFLAG(CS_GET_TASK_ALLOW),
                            CSFLAG(CS_INSTALLER),
                            CSFLAG(CS_FORCED_LV),
                            CSFLAG(CS_INVALID_ALLOWED),
                            CSFLAG(CS_HARD),
                            CSFLAG(CS_KILL),
                            CSFLAG(CS_CHECK_EXPIRATION),
                            CSFLAG(CS_RESTRICT),
                            CSFLAG(CS_ENFORCEMENT),
                            CSFLAG(CS_REQUIRE_LV),
                            CSFLAG(CS_ENTITLEMENTS_VALIDATED),
                            CSFLAG(CS_NVRAM_UNRESTRICTED),
                            CSFLAG(CS_RUNTIME),
                            CSFLAG(CS_LINKER_SIGNED),
                            CSFLAG(CS_ALLOWED_MACHO),
                            CSFLAG(CS_EXEC_SET_HARD),
                            CSFLAG(CS_EXEC_SET_KILL),
                            CSFLAG(CS_EXEC_SET_ENFORCEMENT),
                            CSFLAG(CS_EXEC_INHERIT_SIP),
                            CSFLAG(CS_KILLED),
                            CSFLAG(CS_DYLD_PLATFORM),
                            CSFLAG(CS_PLATFORM_BINARY),
                            CSFLAG(CS_PLATFORM_PATH),
                            CSFLAG(CS_DEBUGGED),
                            CSFLAG(CS_SIGNED),
                            CSFLAG(CS_DEV_CODE)};

NSString *_Nonnull codesigning_flags_str(const uint32_t codesigning_flags) {
  NSMutableArray *match_flags = [NSMutableArray new];

  // Test which code signing flags have been set and add the matched ones to an
  // array
  for (uint32_t i = 0; i < (sizeof g_csFlags / sizeof *g_csFlags); i++) {
    if ((codesigning_flags & g_csFlags[i].value) == g_csFlags[i].value) {
      [match_flags addObject:g_csFlags[i].name];
    }
  }

  return [match_flags componentsJoinedByString:@","];
}

NSString *_Nonnull esstring_to_nsstring(
    const es_string_token_t es_string_token) {
  if (es_string_token.data && es_string_token.length > 0) {
    // es_string_token.data is a pointer to a null-terminated string
    return [NSString stringWithUTF8String:es_string_token.data];
  } else {
    return @"";
  }
}

const NSString *_Nonnull event_type_str(const es_event_type_t event_type) {
  static const NSString *names[] = {
      // The following events are available beginning in macOS 10.15
      @"AUTH_EXEC", @"AUTH_OPEN", @"AUTH_KEXTLOAD", @"AUTH_MMAP",
      @"AUTH_MPROTECT", @"AUTH_MOUNT", @"AUTH_RENAME", @"AUTH_SIGNAL",
      @"AUTH_UNLINK", @"NOTIFY_EXEC", @"NOTIFY_OPEN", @"NOTIFY_FORK",
      @"NOTIFY_CLOSE", @"NOTIFY_CREATE", @"NOTIFY_EXCHANGEDATA", @"NOTIFY_EXIT",
      @"NOTIFY_GET_TASK", @"NOTIFY_KEXTLOAD", @"NOTIFY_KEXTUNLOAD",
      @"NOTIFY_LINK", @"NOTIFY_MMAP", @"NOTIFY_MPROTECT", @"NOTIFY_MOUNT",
      @"NOTIFY_UNMOUNT", @"NOTIFY_IOKIT_OPEN", @"NOTIFY_RENAME",
      @"NOTIFY_SETATTRLIST", @"NOTIFY_SETEXTATTR", @"NOTIFY_SETFLAGS",
      @"NOTIFY_SETMODE", @"NOTIFY_SETOWNER", @"NOTIFY_SIGNAL", @"NOTIFY_UNLINK",
      @"NOTIFY_WRITE", @"AUTH_FILE_PROVIDER_MATERIALIZE",
      @"NOTIFY_FILE_PROVIDER_MATERIALIZE", @"AUTH_FILE_PROVIDER_UPDATE",
      @"NOTIFY_FILE_PROVIDER_UPDATE", @"AUTH_READLINK", @"NOTIFY_READLINK",
      @"AUTH_TRUNCATE", @"NOTIFY_TRUNCATE", @"AUTH_LINK", @"NOTIFY_LOOKUP",
      @"AUTH_CREATE", @"AUTH_SETATTRLIST", @"AUTH_SETEXTATTR", @"AUTH_SETFLAGS",
      @"AUTH_SETMODE", @"AUTH_SETOWNER",

      // The following events are available beginning in macOS 10.15.1
      @"AUTH_CHDIR", @"NOTIFY_CHDIR", @"AUTH_GETATTRLIST",
      @"NOTIFY_GETATTRLIST", @"NOTIFY_STAT", @"NOTIFY_ACCESS", @"AUTH_CHROOT",
      @"NOTIFY_CHROOT", @"AUTH_UTIMES", @"NOTIFY_UTIMES", @"AUTH_CLONE",
      @"NOTIFY_CLONE", @"NOTIFY_FCNTL", @"AUTH_GETEXTATTR",
      @"NOTIFY_GETEXTATTR", @"AUTH_LISTEXTATTR", @"NOTIFY_LISTEXTATTR",
      @"AUTH_READDIR", @"NOTIFY_READDIR", @"AUTH_DELETEEXTATTR",
      @"NOTIFY_DELETEEXTATTR", @"AUTH_FSGETPATH", @"NOTIFY_FSGETPATH",
      @"NOTIFY_DUP", @"AUTH_SETTIME", @"NOTIFY_SETTIME", @"NOTIFY_UIPC_BIND",
      @"AUTH_UIPC_BIND", @"NOTIFY_UIPC_CONNECT", @"AUTH_UIPC_CONNECT",
      @"AUTH_EXCHANGEDATA", @"AUTH_SETACL", @"NOTIFY_SETACL",

      // The following events are available beginning in macOS 10.15.4
      @"NOTIFY_PTY_GRANT", @"NOTIFY_PTY_CLOSE", @"AUTH_PROC_CHECK",
      @"NOTIFY_PROC_CHECK", @"AUTH_GET_TASK",

      // The following events are available beginning in macOS 11.0
      @"AUTH_SEARCHFS", @"NOTIFY_SEARCHFS", @"AUTH_FCNTL", @"AUTH_IOKIT_OPEN",
      @"AUTH_PROC_SUSPEND_RESUME", @"NOTIFY_PROC_SUSPEND_RESUME",
      @"NOTIFY_CS_INVALIDATED", @"NOTIFY_GET_TASK_NAME", @"NOTIFY_TRACE",
      @"NOTIFY_REMOTE_THREAD_CREATE", @"AUTH_REMOUNT", @"NOTIFY_REMOUNT",

      // The following events are available beginning in macOS 11.3
      @"AUTH_GET_TASK_READ", @"NOTIFY_GET_TASK_READ",
      @"NOTIFY_GET_TASK_INSPECT",

      // The following events are available beginning in macOS 12.0
      @"NOTIFY_SETUID", @"NOTIFY_SETGID", @"NOTIFY_SETEUID", @"NOTIFY_SETEGID",
      @"NOTIFY_SETREUID", @"NOTIFY_SETREGID", @"AUTH_COPYFILE",
      @"NOTIFY_COPYFILE"};

  if (event_type >= ES_EVENT_TYPE_LAST) {
    return [NSString
        stringWithFormat:@"Unknown/Unsupported event type: %d", event_type];
  }

  return names[event_type];
}

NSString *_Nonnull events_str(size_t count,
                              const es_event_type_t *_Nonnull events) {
  NSMutableArray *arr = [NSMutableArray new];

  for (size_t i = 0; i < count; i++) {
    [arr addObject:event_type_str(events[i])];
  }

  return [arr componentsJoinedByString:@", "];
}

// On macOS Big Sur 11, Apple have deprecated es_copy_message in favour of
// es_retain_message
es_message_t *_Nonnull copy_message(const es_message_t *_Nonnull msg) {
#if __MAC_OS_X_VERSION_MAX_ALLOWED > 110000
  es_retain_message(msg);
  return (es_message_t *)msg;
#else
  return es_copy_message(msg);
#endif
}

// On macOS Big Sur 11, Apple have deprecated es_free_message in favour of
// es_release_message
void free_message(es_message_t *_Nonnull msg) {
#if __MAC_OS_X_VERSION_MAX_ALLOWED > 110000
  es_release_message(msg);
#else
  es_free_message(msg);
#endif
}

NSString *_Nonnull fdtype_str(const uint32_t fdtype) {
  switch (fdtype) {
  case PROX_FDTYPE_ATALK:
    return @"ATALK";
  case PROX_FDTYPE_VNODE:
    return @"VNODE";
  case PROX_FDTYPE_SOCKET:
    return @"SOCKET";
  case PROX_FDTYPE_PSHM:
    return @"PSHM";
  case PROX_FDTYPE_PSEM:
    return @"PSEM";
  case PROX_FDTYPE_KQUEUE:
    return @"KQUEUE";
  case PROX_FDTYPE_PIPE:
    return @"PIPE";
  case PROX_FDTYPE_FSEVENTS:
    return @"FSEVENTS";
  case PROX_FDTYPE_NETPOLICY:
    return @"NETPOLICY";
  default:
    return
        [NSString stringWithFormat:@"Unknown/Unsupported fdtype: %d", fdtype];
  }
}

bool is_system_file(const NSString *_Nonnull path) {
  // For the purpose of this demo. A system file is a file that is under these
  // directories:
  for (NSString *prefix in @[ @"/System/", @"/usr/share/" ]) {
    if ([path hasPrefix:prefix]) {
      return true;
    }
  }

  return false;
}

bool is_plain_text_file(const NSString *_Nonnull path) {
#if __MAC_OS_X_VERSION_MAX_ALLOWED > 110000
  UTType *utt = [UTType typeWithFilenameExtension:[path pathExtension]];
  return [utt conformsToType:UTTypePlainText];
#else
  return [[NSWorkspace sharedWorkspace] filenameExtension:[path pathExtension]
                                           isValidForType:@"public.plain-text"];
#endif
}

char *_Nonnull filetype_str(const mode_t st_mode) {
  switch (((st_mode)&S_IFMT)) {
  case S_IFBLK:
    return "BLK";
  case S_IFCHR:
    return "CHR";
  case S_IFDIR:
    return "DIR";
  case S_IFIFO:
    return "FIFO";
  case S_IFREG:
    return "REG";
  case S_IFLNK:
    return "LINK";
  case S_IFSOCK:
    return "SOCK";
  default:
    return "";
  }
}
