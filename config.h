#import <Foundation/Foundation.h>
@interface Config : NSDictionary

@property(nonatomic, strong) NSString *config_file_path;
@property(nonatomic, strong) NSMutableDictionary *config;
- (instancetype)initWithConfigPath:(NSString *)config_file_path;
@end
