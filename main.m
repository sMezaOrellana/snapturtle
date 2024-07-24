#import <Appkit/AppKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <Kernel/kern/cs_blobs.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <bsm/libbsm.h>
#import <libproc.h>
#import <mach/mach_time.h>
#import <signal.h>
#include <stdint.h>
#pragma mark Globals
NSFileHandle *file_handle = nil;
es_client_t *g_client = nil;
NSSet *g_blocked_paths = nil;
NSDateFormatter *g_date_formater = nil;

// Endpoint Security event handler selected at startup from the command line
es_handler_block_t g_handler = nil;

// Used to detect if any events have been dropped by the kernel
uint64_t g_global_seq_num = 0;
NSMutableDictionary *g_seq_nums = nil;

// Set to true if want to cache the results of an auth event response
bool g_cache_auth_results = false;

// Logs can become quite busy, especially when subscribing to
// ES_EVENT_TYPE_AUTH_OPEN events. Only log all event messages when the flag is
// enabled; otherwise only denied Auth event messages will be logged.
bool g_verbose_logging = false;

#pragma mark Helpers - Mach Absolute Time

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

NSString *SHA1ForFileAtPath(NSString *filePath) {
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

#pragma mark Helpers - Code Signing

typedef struct {
  const NSString *name;
  int value;
} CSFlag;

#define CSFLAG(flag)                                                           \
  { @ #flag, flag }

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

NSString *codesigning_flags_str(const uint32_t codesigning_flags) {
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

#pragma mark Helpers - Endpoint Security

NSString *esstring_to_nsstring(const es_string_token_t es_string_token) {
  if (es_string_token.data && es_string_token.length > 0) {
    // es_string_token.data is a pointer to a null-terminated string
    return [NSString stringWithUTF8String:es_string_token.data];
  } else {
    return @"";
  }
}

const NSString *event_type_str(const es_event_type_t event_type) {
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

NSString *events_str(size_t count, const es_event_type_t *events) {
  NSMutableArray *arr = [NSMutableArray new];

  for (size_t i = 0; i < count; i++) {
    [arr addObject:event_type_str(events[i])];
  }

  return [arr componentsJoinedByString:@", "];
}

// On macOS Big Sur 11, Apple have deprecated es_copy_message in favour of
// es_retain_message
es_message_t *copy_message(const es_message_t *msg) {
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

#pragma mark Helpers - Misc

NSString *fdtype_str(const uint32_t fdtype) {
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

bool is_system_file(const NSString *path) {
  // For the purpose of this demo. A system file is a file that is under these
  // directories:
  for (NSString *prefix in @[ @"/System/", @"/usr/share/" ]) {
    if ([path hasPrefix:prefix]) {
      return true;
    }
  }

  return false;
}

bool is_plain_text_file(const NSString *path) {
#if __MAC_OS_X_VERSION_MAX_ALLOWED > 110000
  UTType *utt = [UTType typeWithFilenameExtension:[path pathExtension]];
  return [utt conformsToType:UTTypePlainText];
#else
  return [[NSWorkspace sharedWorkspace] filenameExtension:[path pathExtension]
                                           isValidForType:@"public.plain-text"];
#endif
}

char *filetype_str(const mode_t st_mode) {
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

#pragma mark - Logging

#define BOOL_VALUE(x) x ? "Yes" : "No"

int g_log_indent = 0;
#define LOG_INDENT_INC()                                                       \
  { g_log_indent += 2; }
#define LOG_INDENT_DEC()                                                       \
  { g_log_indent -= 2; }

#define LOG_IMPORTANT_INFO(fmt, ...)                                           \
  NSLog(@"*** " @ #fmt @" ***", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) NSLog(@"%*s" @ #fmt, g_log_indent, "", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) NSLog(@"ERROR: " @ #fmt, ##__VA_ARGS__)

API_AVAILABLE(macos(12.0))
bool log_muted_paths_events(void) {
  es_muted_paths_t *muted_paths = NULL;
  es_return_t result = es_muted_paths_events(g_client, &muted_paths);

  if (ES_RETURN_SUCCESS != result) {
    LOG_ERROR("es_muted_paths_events: ES_RETURN_ERROR");
    return false;
  }

  if (NULL == muted_paths) {
    // There are no muted paths
    return true;
  }

  LOG_IMPORTANT_INFO("Muted Paths");
  for (size_t i = 0; i < muted_paths->count; i++) {
    es_muted_path_t muted_path = muted_paths->paths[i];
    LOG_INFO("muted_path[%ld]: %@", i, esstring_to_nsstring(muted_path.path));

    if (g_verbose_logging) {
      LOG_INDENT_INC();
      LOG_INFO("type: %s", (muted_path.type == ES_MUTE_PATH_TYPE_PREFIX)
                               ? "Prefix"
                               : "Literal");
      LOG_INFO("event_count: %ld", muted_path.event_count);
      LOG_INFO("events: %@",
               events_str(muted_path.event_count, muted_path.events));
      LOG_INDENT_DEC();
    }
  }

  es_release_muted_paths(muted_paths);
  return true;
}

bool log_subscribed_events(void) {
  // Log the subscribed events
  size_t count = 0;
  es_event_type_t *events = NULL;
  es_return_t result = es_subscriptions(g_client, &count, &events);

  if (ES_RETURN_SUCCESS != result) {
    LOG_ERROR("es_subscriptions: ES_RETURN_ERROR");
    return false;
  }

  LOG_IMPORTANT_INFO("Subscribed Events: %@", events_str(count, events));

  free(events);
  return true;
}

NSDictionary *audit_token_to_dict(const audit_token_t *audit_token) {
  return @{
    @"pid" : @(audit_token_to_pid(*audit_token)),
    @"ruid" : @(audit_token_to_ruid(*audit_token)),
    @"euid" : @(audit_token_to_euid(*audit_token)),
    @"rgid" : @(audit_token_to_rgid(*audit_token)),
    @"egid" : @(audit_token_to_egid(*audit_token)),
  };
}

NSDictionary *stat_to_dictionary(const struct stat *stat) {
  return @{
    @"st_dev" : @(stat->st_dev),
    @"st_ino" : @(stat->st_ino),
    @"st_mode" : @(stat->st_mode),
    @"st_nlink" : @(stat->st_nlink),
    @"st_uid" : @(stat->st_uid),
    @"st_gid" : @(stat->st_gid),
    @"st_atime" : formatted_date_str(stat->st_atime),
    @"st_mtime" : formatted_date_str(stat->st_mtime),
    @"st_ctime" : formatted_date_str(stat->st_ctime),
    @"st_birthtime" : formatted_date_str(stat->st_birthtime),
    @"st_size" : @(stat->st_size),
    @"st_blocks" : @(stat->st_blocks),
    @"st_blksize" : @(stat->st_blksize),
    @"st_flags" : @(stat->st_flags),
    @"st_gen" : @(stat->st_gen),
  };
}

NSDictionary *es_file_t_to_dict(const es_file_t *file) {
  NSString *file_path = esstring_to_nsstring(file->path);
  NSString *process_sha1;

  if (S_ISREG(file->stat.st_mode) && file->stat.st_size < 40000000) {
    file_path = esstring_to_nsstring(file->path);
    process_sha1 = SHA1ForFileAtPath(file_path);
  } else {
    process_sha1 = @"";
  }
  return @{
    @"path" : esstring_to_nsstring(file->path),
    @"path_truncated" : @(BOOL_VALUE(file->path_truncated)),
    @"stat" : stat_to_dictionary(&(file->stat)),
    @"sha1" : process_sha1,
  };
}

NSDictionary *es_process_t_to_dict(const es_process_t *proc) {

  NSString *path = esstring_to_nsstring(proc->executable->path);
  NSString *process_sha1 = SHA1ForFileAtPath(path);
  return @{
    @"proc" : @{
      @"audit_token" : audit_token_to_dict(&(proc->audit_token)),
      @"ppid" : @(proc->ppid),
      @"original_ppid" : @(proc->original_ppid),
      @"group_id" : @(proc->group_id),
      @"session_id" : @(proc->session_id),
      @"is_platform_binary" : @(BOOL_VALUE(proc->is_platform_binary)),
      @"is_es_client" : @(BOOL_VALUE(proc->is_es_client)),
      @"signing_id" : esstring_to_nsstring(proc->signing_id),
      @"team_id" : esstring_to_nsstring(proc->team_id),
      @"codesigning_flags" : codesigning_flags_str(proc->codesigning_flags),
      @"executable" : es_file_t_to_dict(proc->executable),
      @"sha1" : process_sha1,
    }
  };
}

NSMutableArray *
exec_command_line_arguments_to_array(const es_event_exec_t *exec) {
  NSMutableArray *list = [NSMutableArray array];

  uint32_t arg_count = es_exec_arg_count(exec);
  for (uint32_t i = 0; i < arg_count; i++) {
    es_string_token_t arg = es_exec_arg(exec, i);
    [list addObject:esstring_to_nsstring(arg)];
  }
  return list;
}

NSDictionary *es_event_exec_to_dict(const es_event_exec_t *exec) {

  return @{
    @"target" : es_process_t_to_dict(exec->target),
    @"command_line_arguments" : exec_command_line_arguments_to_array(exec),

  };
}

NSDictionary *es_event_open_to_dict(const es_event_open_t *open) {
  NSMutableArray *match_flags = [NSMutableArray new];

  if ((open->fflag & FREAD) == FREAD) {
    [match_flags addObject:@"FREAD"];
  }

  if ((open->fflag & FWRITE) == FWRITE) {
    [match_flags addObject:@"FWRITE"];
  }

  return @{
    @"match_flags" : match_flags,
    @"open_file" : es_file_t_to_dict(open->file),
  };
}

NSDictionary *event_to_dict(const es_message_t *msg) {
  switch (msg->event_type) {
  case ES_EVENT_TYPE_AUTH_EXEC: {
    return es_event_exec_to_dict(&msg->event.exec);
  } break;

  case ES_EVENT_TYPE_AUTH_OPEN: {
    return es_event_open_to_dict(&msg->event.open);
  } break;

  case ES_EVENT_TYPE_NOTIFY_FORK: {
  } break;

  case ES_EVENT_TYPE_LAST:
  default: {
  }
  }
  return @{};
}

NSDictionary *event_message_to_dict(const es_message_t *msg) {
  return @{
    @"event_type" : event_type_str(msg->event_type),
    @"process" : es_process_t_to_dict(msg->process),
    @"version" : @(msg->version),
    @"time" : formatted_date_str(msg->time.tv_sec),
    @"mach_time" : @(msg->mach_time),
    @"deadline" : @(msg->deadline),
    @"event" : event_to_dict(msg),
  };
}
// Demonstrates detecting dropped event messages from the kernel, by either
// using the using the seq_num or global_seq_num fields in an event message
void detect_and_log_dropped_events(const es_message_t *msg) {
  uint32_t version = msg->version;

  // Note: You can use the seq_num field to detect if the kernel had to
  // drop any event messages, for an event type, to the client.
  if (version >= 2) {
    uint64_t seq_num = msg->seq_num;

    const NSString *type = event_type_str(msg->event_type);
    NSNumber *last_seq_num = [g_seq_nums objectForKey:type];

    if (last_seq_num != nil) {
      uint64_t expected_seq_num = [last_seq_num unsignedLongLongValue] + 1;

      if (seq_num > expected_seq_num) {
        LOG_ERROR("EVENTS DROPPED! seq_num is ahead by: %llu",
                  (seq_num - expected_seq_num));
      }
    }

    [g_seq_nums setObject:[NSNumber numberWithUnsignedLong:seq_num]
                   forKey:type];
  }

  // Note: You can use the global_seq_num field to detect if the kernel had to
  // drop any event messages to the client.
  if (version >= 4) {
    uint64_t global_seq_num = msg->global_seq_num;

    if (global_seq_num > ++g_global_seq_num) {
      LOG_ERROR("EVENTS DROPPED! global_seq_num is ahead by: %llu",
                (global_seq_num - g_global_seq_num));
      g_global_seq_num = global_seq_num;
    }
  }
}

#pragma mark - Endpoint Secuirty Demo

// Clean-up before exiting
void sig_handler(int sig) {
  LOG_IMPORTANT_INFO("Tidying Up");

  if (g_client) {
    es_unsubscribe_all(g_client);
    es_delete_client(g_client);
  }

  [g_blocked_paths release];
  [file_handle closeFile];
  [file_handle release];
  LOG_IMPORTANT_INFO("Exiting");
  exit(EXIT_SUCCESS);
}

void print_usage(const char *name) {
  printf("Usage: %s (verbose)\n", name);
  printf("Arguments:\n");
  printf("\tverbose\t\tTurns on verbose logging\n");
}

// An example handler to make auth (allow or block) decisions.
// Returns either an ES_AUTH_RESULT_ALLOW or ES_AUTH_RESULT_DENY.
es_auth_result_t auth_event_handler(const es_message_t *msg) {
  // NOTE: You should ignore events from other ES Clients;
  // otherwise you may trigger more events causing a potentially infinite cycle.
  if (msg->process->is_es_client) {
    return ES_AUTH_RESULT_ALLOW;
  }

  // Ignore events from root processes
  if (0 == audit_token_to_ruid(msg->process->audit_token)) {
    return ES_AUTH_RESULT_ALLOW;
  }

  // Block exec if path of process is in our blocked paths list
  if (ES_EVENT_TYPE_AUTH_EXEC == msg->event_type) {

    NSString *path =
        esstring_to_nsstring(msg->event.exec.target->executable->path);

    if (![g_blocked_paths containsObject:path]) {
      return ES_AUTH_RESULT_ALLOW;
    }

    LOG_IMPORTANT_INFO("BLOCKING EXEC: %@", path);
    return ES_AUTH_RESULT_DENY;
  }

  if (ES_EVENT_TYPE_AUTH_OPEN == msg->event_type) {

    return ES_AUTH_RESULT_ALLOW;
  }

  // All good
  return ES_AUTH_RESULT_ALLOW;
}

// Sends a response back to Endpoint Security for an auth event
// Note: You must always send a response back before the deadline expires.
void respond_to_auth_event(es_client_t *clt, const es_message_t *msg,
                           es_auth_result_t result) {

  if (ES_EVENT_TYPE_AUTH_OPEN == msg->event_type) {

    es_respond_result_t res = es_respond_flags_result(
        clt, msg, UINT32_MAX, false); // g_cache_auth_results);

    if (ES_RESPOND_RESULT_SUCCESS != res) {
      LOG_ERROR("es_respond_flags_result: %d", res);
    }

  } else {
    es_respond_result_t res = es_respond_auth_result(clt, msg, result, false);

    if (ES_RESPOND_RESULT_SUCCESS != res) {
      LOG_ERROR("es_respond_auth_result: %d", res);
    }
  }
}

// Example of an event message handler to process event messages asynchronously
// from Endpoint Security
es_handler_block_t message_handler = ^(es_client_t *clt,
                                       const es_message_t *msg) {
  // Endpoint Security, by default, calls a event message handler serially
  // for each message. We copy/retain the message so that we can process and
  // respond to auth events asynchronously.

  // NOTE: It is important to process events in a timely manner.
  // The kernel will start to drop events for the client if they are not
  // responded to in time.
  detect_and_log_dropped_events(msg);

  // Copy/Retain the event message so that we process the event
  // asynchronously
  es_message_t *copied_msg = copy_message(msg);

  if (!copied_msg) {
    LOG_ERROR("Failed to copy message");
    return;
  }

  dispatch_async(
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0),
      ^(void) {
        es_auth_result_t result = auth_event_handler(copied_msg);

        if (ES_ACTION_TYPE_AUTH == copied_msg->action_type) {
          respond_to_auth_event(clt, copied_msg, result);
        }
        dispatch_async(
            dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
              NSDictionary *event_dict = event_message_to_dict(copied_msg);
              if ([NSJSONSerialization isValidJSONObject:event_dict]) {
                NSError *error;
                NSData *jsonData = [NSJSONSerialization
                    dataWithJSONObject:event_dict
                               options:NSJSONWritingPrettyPrinted
                                 error:&error];

                if (!jsonData) {
                  NSLog(@"Got an error: %@", error);
                } else {
                  NSString *jsonString =
                      [[NSString alloc] initWithData:jsonData
                                            encoding:NSUTF8StringEncoding];

                  NSString *jsonLine =
                      [jsonString stringByAppendingString:@"\n"];

                  [file_handle
                      writeData:[jsonLine
                                    dataUsingEncoding:NSUTF8StringEncoding]];
                }
              }
              free_message(copied_msg);
            });
      });
};

// On macOS Monterey 12, Apple have deprecated es_mute_path_literal in favour of
// es_mute_path
bool mute_path(const char *path) {
  es_return_t result = ES_RETURN_ERROR;

#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 120000
  result = es_mute_path(g_client, path, ES_MUTE_PATH_TYPE_LITERAL);
#else
  result = es_mute_path_literal(g_client, path);

#endif
  if (ES_RETURN_SUCCESS != result) {
    LOG_ERROR("mute_path: ES_RETURN_ERROR");
    return false;
  }
  return true;
}

// Note: This function shows the boilerplate code required to setup a
// connection to Endpoint Security and subscribe to events.
bool setup_endpoint_security(void) {
  // Create a new client with an associated event message handler.
  // Requires 'com.apple.developer.endpoint-security.client' entitlement.
  es_new_client_result_t res = es_new_client(&g_client, g_handler);

  if (ES_NEW_CLIENT_RESULT_SUCCESS != res) {
    switch (res) {
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
      LOG_ERROR("Application requires "
                "'com.apple.developer.endpoint-security.client' entitlement");
      break;

    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
      LOG_ERROR("Application lacks Transparency, Consent, and Control (TCC) "
                "approval "
                "from the user. This can be resolved by granting 'Full Disk "
                "Access' "
                "from "
                "the 'Security & Privacy' tab of System Preferences.");
      break;

    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
      LOG_ERROR("Application needs to be run as root");
      break;

    default:
      LOG_ERROR("es_new_client: %d", res);
    }

    return false;
  }

  // Explicitly clear the cache of previous cached results from this demo or
  // other ES Clients
  es_clear_cache_result_t resCache = es_clear_cache(g_client);
  if (ES_CLEAR_CACHE_RESULT_SUCCESS != resCache) {
    LOG_ERROR("es_clear_cache: %d", resCache);
    return false;
  }

  // Subscribe to the events we're interested in
  es_event_type_t events[] = {ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_EXEC};
  //, ES_EVENT_TYPE_AUTH_OPEN,
  // ES_EVENT_TYPE_NOTIFY_FORK};

  es_return_t subscribed =
      es_subscribe(g_client, events, sizeof events / sizeof *events);

  if (ES_RETURN_ERROR == subscribed) {
    LOG_ERROR("es_subscribe: ES_RETURN_ERROR");
    return false;
  }

  // All good
  return log_subscribed_events();
}

int main(int argc, const char *argv[]) {
  signal(SIGINT, &sig_handler);

  NSString *logs_file_path =
      [[NSFileManager defaultManager] currentDirectoryPath];
  logs_file_path = [logs_file_path stringByAppendingPathComponent:@"logs"];

  // Open the file for appending
  file_handle = [NSFileHandle fileHandleForWritingAtPath:logs_file_path];
  if (!file_handle) {
    [[NSFileManager defaultManager] createFileAtPath:logs_file_path
                                            contents:nil
                                          attributes:nil];
    file_handle = [NSFileHandle fileHandleForWritingAtPath:logs_file_path];
  }

  if (!file_handle) {
    NSLog(@"Error opening (%@)", logs_file_path);
  }

  [file_handle retain];

  @autoreleasepool {
    // Init global vars
    g_handler = message_handler;

    if (!g_handler) {
      print_usage(argv[0]);
      return 1;
    }

    init_date_formater();
    g_seq_nums = [NSMutableDictionary new];
    // List of paths to be blocked.
    // For this demo we will block the top binary and Calculator app bundle.
    g_blocked_paths = [NSSet
        setWithObjects:
            @"/usr/bin/top",
            @"/System/Applications/Calculator.app/Contents/MacOS/Calculator",
            nil];

    // had to do this otherwise it seems that the memory is free'd and this
    // leads to a segfault
    [g_blocked_paths retain];

    if (!setup_endpoint_security()) {
      return 1;
    }
#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 120000
    log_muted_paths_events();
#else
    mute_path("/usr/sbin/cfprefsd");
#endif

    // Start handling events from Endpoint Security
    dispatch_main();
  }

  return 0;
}
