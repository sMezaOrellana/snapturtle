#import "eventdatatypes.h"
#import "shared.h"

#pragma mark Globals
NSFileHandle *file_handle = nil;
es_client_t *g_client = nil;
NSSet *g_blocked_paths = nil;

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
