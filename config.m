#import "config.h"
@interface Config ()

- (BOOL)validateConfigDictionary:(NSDictionary *)config_dict;

@end

@implementation Config
- (instancetype)initWithConfigPath:(NSString *)config_file_path {

  // TODO: check that all of this shit does not return any errors
  self = [super init];
  // TODO: validate config_file_path
  NSError *error = nil;

  // Read the content of the file into a string
  NSString *config_file_content =
      [NSString stringWithContentsOfFile:config_file_path
                                encoding:NSUTF8StringEncoding
                                   error:&error];

  if (error) {
    NSLog(@"Error reading file: %@", [error localizedDescription]);
  } else {
    // Successfully read the file content
    NSLog(@"File Content:\n%@", config_file_content);
  }

  NSData *config_data =
      [config_file_content dataUsingEncoding:NSUTF8StringEncoding];

  NSLog(@"%@", config_data);

  id config_nsobject =
      [NSJSONSerialization JSONObjectWithData:config_data
                                      options:NSJSONReadingMutableContainers
                                        error:&error];
  if (error) {
    NSLog(@"Error parsing JSON: %@", error);
  }

  NSDictionary *config_dict = (NSDictionary *)config_nsobject;
  NSLog(@"%@", config_nsobject);

  BOOL res = [self validateConfigDictionary:config_dict];

  _config = [config_dict mutableCopy];

  return self;
}
- (BOOL)validateConfigDictionary:(NSDictionary *)dictionary {
  // Check if the top-level dictionary contains "events" key
  NSArray *events = dictionary[@"events"];
  if (![events isKindOfClass:[NSArray class]]) {
    NSLog(@"Missing or invalid 'events' key");
    return NO;
  }

  // Check if the "enrichment" dictionary is present and valid
  NSDictionary *enrichment = dictionary[@"enrichment"];
  if (![enrichment isKindOfClass:[NSDictionary class]]) {
    NSLog(@"Missing or invalid 'enrichment' key");
    return NO;
  }

  // Check if the "hashes" dictionary is present within "enrichment"
  NSDictionary *hashes = enrichment[@"hashes"];
  if (![hashes isKindOfClass:[NSDictionary class]]) {
    NSLog(@"Missing or invalid 'hashes' key in 'enrichment'");
    return NO;
  }

  // Check if the "sha1" dictionary is present within "hashes"
  NSDictionary *sha1 = hashes[@"sha1"];
  if (![sha1 isKindOfClass:[NSDictionary class]]) {
    NSLog(@"Missing or invalid 'sha1' key in 'hashes'");
    return NO;
  }

  // Check if the "max_file_size" string is present within "sha1"
  NSString *maxFileSize = sha1[@"max_file_size"];
  if (![maxFileSize isKindOfClass:[NSString class]]) {
    NSLog(@"Missing or invalid 'max_file_size' key in 'sha1'");
    return NO;
  }

  // Check if the "block_list" dictionary is present and valid
  NSDictionary *blockList = dictionary[@"block_list"];
  if (![blockList isKindOfClass:[NSDictionary class]]) {
    NSLog(@"Missing or invalid 'block_list' key");
    return NO;
  }

  // Check if the "paths" array is present within "block_list"
  NSArray *paths = blockList[@"paths"];
  if (![paths isKindOfClass:[NSArray class]]) {
    NSLog(@"Missing or invalid 'paths' key in 'block_list'");
    return NO;
  }

  // If all checks pass, return YES
  return YES;
}

@end
