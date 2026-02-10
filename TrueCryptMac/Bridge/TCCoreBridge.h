/*
 Copyright (c) 2024 TrueCrypt macOS Port. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

// ObjC++ bridge between libTrueCryptCore (C++) and the SwiftUI app.
// Converts C++ exceptions → NSError, C++ types → Foundation types.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSErrorDomain const TCErrorDomain;

// ---- Volume Info (read-only snapshot of a mounted volume) ----

@interface TCVolumeInfo : NSObject

@property (nonatomic, readonly) NSInteger slotNumber;
@property (nonatomic, readonly, copy) NSString *path;
@property (nonatomic, readonly, copy) NSString *mountPoint;
@property (nonatomic, readonly, copy) NSString *virtualDevice;
@property (nonatomic, readonly) uint64_t size;
@property (nonatomic, readonly, copy) NSString *encryptionAlgorithmName;
@property (nonatomic, readonly, copy) NSString *encryptionModeName;
@property (nonatomic, readonly, copy) NSString *pkcs5PrfName;
@property (nonatomic, readonly) uint32_t pkcs5IterationCount;
@property (nonatomic, readonly) BOOL isHiddenVolume;
@property (nonatomic, readonly) BOOL isReadOnly;
@property (nonatomic, readonly) BOOL hiddenVolumeProtectionTriggered;
@property (nonatomic, readonly) BOOL systemEncryption;
@property (nonatomic, readonly) uint64_t totalDataRead;
@property (nonatomic, readonly) uint64_t totalDataWritten;

@end

// ---- Host Device Info ----

@interface TCHostDevice : NSObject

@property (nonatomic, readonly, copy) NSString *path;
@property (nonatomic, readonly, copy) NSString *mountPoint;
@property (nonatomic, readonly, copy) NSString *name;
@property (nonatomic, readonly) uint64_t size;
@property (nonatomic, readonly) BOOL removable;
@property (nonatomic, readonly, copy) NSArray<TCHostDevice *> *partitions;

@end

// ---- Mount Options ----

@interface TCMountOptions : NSObject

@property (nonatomic, copy, nullable) NSString *volumePath;
@property (nonatomic, copy, nullable) NSString *mountPoint;
@property (nonatomic, copy, nullable) NSString *password;
@property (nonatomic, copy, nullable) NSArray<NSString *> *keyfilePaths;
@property (nonatomic) NSInteger slotNumber;
@property (nonatomic) BOOL readOnly;
@property (nonatomic) BOOL useBackupHeaders;
@property (nonatomic) BOOL noFilesystem;
@property (nonatomic) BOOL preserveTimestamps;
@property (nonatomic) BOOL sharedAccessAllowed;

// Hidden volume protection
@property (nonatomic) BOOL protectHiddenVolume;
@property (nonatomic, copy, nullable) NSString *protectionPassword;
@property (nonatomic, copy, nullable) NSArray<NSString *> *protectionKeyfilePaths;

@end

// ---- Volume Creation Options ----

typedef NS_ENUM(NSInteger, TCVolumeType) {
    TCVolumeTypeNormal = 0,
    TCVolumeTypeHidden = 1
};

typedef NS_ENUM(NSInteger, TCFilesystemType) {
    TCFilesystemTypeNone = 0,
    TCFilesystemTypeFAT = 1,
    TCFilesystemTypeMacOsExt = 2
};

@interface TCVolumeCreationOptions : NSObject

@property (nonatomic, copy) NSString *path;
@property (nonatomic) TCVolumeType volumeType;
@property (nonatomic) uint64_t size;
@property (nonatomic, copy, nullable) NSString *password;
@property (nonatomic, copy, nullable) NSArray<NSString *> *keyfilePaths;
@property (nonatomic, copy, nullable) NSString *encryptionAlgorithm;
@property (nonatomic, copy, nullable) NSString *hashAlgorithm;
@property (nonatomic) TCFilesystemType filesystem;
@property (nonatomic) BOOL quickFormat;
@property (nonatomic) BOOL legacyIterations; // Use TrueCrypt 7.1a iteration counts (1000/2000)

@end

// ---- Volume Creation Progress ----

@interface TCVolumeCreationProgress : NSObject

@property (nonatomic, readonly) BOOL inProgress;
@property (nonatomic, readonly) uint64_t totalSize;
@property (nonatomic, readonly) uint64_t sizeDone;
@property (nonatomic, readonly) double fraction; // 0.0 – 1.0

@end

// ---- Core Bridge (singleton) ----

@interface TCCoreBridge : NSObject

+ (instancetype)shared;

// Lifecycle
- (BOOL)initializeCore:(NSError **)error;

// Volume mounting/dismounting
- (nullable TCVolumeInfo *)mountVolume:(TCMountOptions *)options
                                 error:(NSError **)error;

- (BOOL)dismountVolume:(TCVolumeInfo *)volume
                 force:(BOOL)force
                 error:(NSError **)error;

- (BOOL)dismountAllVolumes:(BOOL)force
                     error:(NSError **)error;

- (BOOL)isVolumeMounted:(NSString *)path;

// Volume queries
- (NSArray<TCVolumeInfo *> *)mountedVolumes;

// Host devices
- (NSArray<TCHostDevice *> *)hostDevices:(NSError **)error;

// Password/keyfile change
- (BOOL)changePasswordForVolume:(NSString *)volumePath
                       password:(NSString *)currentPassword
                       keyfiles:(nullable NSArray<NSString *> *)keyfilePaths
                    newPassword:(NSString *)newPassword
                    newKeyfiles:(nullable NSArray<NSString *> *)newKeyfilePaths
                        newHash:(nullable NSString *)hashName
                          error:(NSError **)error;

// Keyfile creation
- (BOOL)createKeyfile:(NSString *)path error:(NSError **)error;

// Self-test
- (BOOL)runSelfTest:(NSError **)error;

// Available algorithms
- (NSArray<NSString *> *)availableEncryptionAlgorithms;
- (NSArray<NSString *> *)availableHashAlgorithms;

// Volume creation (async with progress)
- (BOOL)startVolumeCreation:(TCVolumeCreationOptions *)options
                      error:(NSError **)error;
- (TCVolumeCreationProgress *)volumeCreationProgress;
- (void)abortVolumeCreation;

// Post-creation filesystem formatting (mounts volume temporarily, runs newfs, dismounts)
- (BOOL)formatVolumeFilesystem:(NSString *)volumePath
                      password:(NSString *)password
                      keyfiles:(nullable NSArray<NSString *> *)keyfilePaths
                    filesystem:(TCFilesystemType)filesystem
                         error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
