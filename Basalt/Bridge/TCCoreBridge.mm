/*
 Copyright (c) 2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

// ObjC/AppKit MUST come first — establishes typedef bool BOOL
// before Tcdefs.h (which now guards its #define BOOL int)
#import <AppKit/AppKit.h>
#import "TCCoreBridge.h"

#include "Core/CorePublicAPI.h"
#include "Core/VolumeOperations.h"
#include "Core/Unix/CoreService.h"
#include "Fuse/FuseService.h"
#include "Volume/EncryptionTest.h"
#include "Platform/PlatformTest.h"
#include "Platform/StringConverter.h"
#include "TCCocoaCallback.h"

#include <string>
#include <memory>

using namespace Basalt;

NSErrorDomain const TCErrorDomain = @"com.truecrypt.core";

// ---- Helper: NSString ↔ wstring ----

static inline NSString *ToNS (const wstring &s)
{
    if (s.empty ()) return @"";
    return [[NSString alloc] initWithBytes:s.data ()
                                    length:s.size () * sizeof (wchar_t)
                                  encoding:NSUTF32LittleEndianStringEncoding];
}

static inline wstring ToWide (NSString *s)
{
    if (!s || s.length == 0) return L"";
    // Use UTF-32 for direct wchar_t conversion
    NSData *data = [s dataUsingEncoding:NSUTF32LittleEndianStringEncoding];
    if (!data) return L"";
    return wstring (reinterpret_cast<const wchar_t *>(data.bytes), data.length / sizeof (wchar_t));
}

// ---- Helper: Admin password prompt (ObjC context) ----

static bool AskAdminPassword (string &passwordOut)
{
    __block NSString *result = nil;

    dispatch_block_t block = ^{
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = NSLocalizedString (@"Administrator privileges required", nil);
        alert.informativeText = NSLocalizedString (@"Basalt needs administrator privileges to mount volumes. Enter your macOS password:", nil);
        alert.alertStyle = NSAlertStyleWarning;
        [alert addButtonWithTitle:NSLocalizedString (@"OK", nil)];
        [alert addButtonWithTitle:NSLocalizedString (@"Cancel", nil)];

        NSSecureTextField *input = [[NSSecureTextField alloc] initWithFrame:NSMakeRect (0, 0, 300, 24)];
        alert.accessoryView = input;
        [alert.window setInitialFirstResponder:input];
        // SECURITY: Prevent screen capture of password dialog
        alert.window.sharingType = NSWindowSharingNone;

        if ([alert runModal] == NSAlertFirstButtonReturn && input.stringValue.length > 0)
            result = input.stringValue;
    };

    if ([NSThread isMainThread])
        block ();
    else
        dispatch_sync (dispatch_get_main_queue (), block);

    if (result)
    {
        passwordOut = string ([result UTF8String]);
        return true;
    }
    return false;
}

// ---- Helper: C++ exception → NSError ----
//
// TrueCrypt exceptions carry SRC_POS ("FunctionName:LineNumber") as their
// message, which is useful for developers but meaningless to users.
// Map known exception types to user-friendly descriptions.

static NSError *ExceptionToError (const std::exception &e)
{
    NSString *desc = nil;
    NSInteger code = TCErrorCodeGeneric;

    // --- Core exceptions (CoreException.h) ---
    if (dynamic_cast <const VolumeAlreadyMounted *> (&e))
        desc = NSLocalizedString (@"The volume is already mounted.", nil);
    else if (dynamic_cast <const MountPointUnavailable *> (&e))
        desc = NSLocalizedString (@"The mount point is already in use.", nil);
    else if (dynamic_cast <const MountPointRequired *> (&e))
        desc = NSLocalizedString (@"A mount point is required.", nil);
    else if (dynamic_cast <const HigherFuseVersionRequired *> (&e))
        desc = NSLocalizedString (@"A newer version of FUSE is required.", nil);
    else if (dynamic_cast <const VolumeSlotUnavailable *> (&e))
        desc = NSLocalizedString (@"The volume slot is unavailable.", nil);
    else if (dynamic_cast <const TemporaryDirectoryFailure *> (&e))
        desc = NSLocalizedString (@"Failed to create a temporary directory.", nil);

    // --- Password exceptions (VolumePassword.h) ---
    // Order matters: most-derived first (PasswordKeyfilesIncorrect before PasswordIncorrect).
    else if (dynamic_cast <const ProtectionPasswordKeyfilesIncorrect *> (&e))
        desc = NSLocalizedString (@"Incorrect password or keyfile(s) for the hidden volume.", nil);
    else if (dynamic_cast <const ProtectionPasswordIncorrect *> (&e))
        desc = NSLocalizedString (@"Incorrect password for the hidden volume.", nil);
    else if (dynamic_cast <const PasswordKeyfilesIncorrect *> (&e))
    {
        desc = NSLocalizedString (@"Incorrect password or keyfile(s).", nil);
        code = TCErrorCodePasswordIncorrect;
    }
    else if (dynamic_cast <const PasswordIncorrect *> (&e))
    {
        desc = NSLocalizedString (@"Incorrect password.", nil);
        code = TCErrorCodePasswordIncorrect;
    }
    else if (dynamic_cast <const PasswordTooLong *> (&e))
        desc = NSLocalizedString (@"The password is too long.", nil);
    else if (dynamic_cast <const PasswordEmpty *> (&e))
        desc = NSLocalizedString (@"No password was provided.", nil);
    else if (dynamic_cast <const UnportablePassword *> (&e))
        desc = NSLocalizedString (@"The new password contains characters that cannot be stored without losing information (characters beyond Latin-1, e.g. €, Cyrillic, Greek, CJK or emoji). They would be truncated and silently weaken the password. Please use letters, digits and symbols from the Latin-1 range.", nil);

    // --- Volume / keyfile / environment errors ---
    else if (dynamic_cast <const MountedVolumeInUse *> (&e))
        desc = NSLocalizedString (@"The volume is in use. Close all files on it, or enable force dismount in Settings.", nil);
    else if (dynamic_cast <const VolumeHostInUse *> (&e))
        desc = NSLocalizedString (@"The volume file is in use by another application.", nil);
    else if (dynamic_cast <const VolumeProtected *> (&e))
        desc = NSLocalizedString (@"The write was blocked to protect the hidden volume.", nil);
    else if (dynamic_cast <const VolumeReadOnly *> (&e))
        desc = NSLocalizedString (@"The volume is read-only.", nil);
    else if (dynamic_cast <const MissingVolumeData *> (&e))
        desc = NSLocalizedString (@"The volume file is incomplete or damaged.", nil);
    else if (dynamic_cast <const UnsupportedSectorSize *> (&e))
        desc = NSLocalizedString (@"The volume uses an unsupported sector size.", nil);
    else if (dynamic_cast <const HigherVersionRequired *> (&e))
        desc = NSLocalizedString (@"This volume was created by a newer version of Basalt.", nil);
    else if (dynamic_cast <const InsufficientData *> (&e))
        desc = NSLocalizedString (@"A keyfile is empty or too small.", nil);
    else if (dynamic_cast <const KeyfilePathEmpty *> (&e))
        desc = NSLocalizedString (@"The selected keyfile folder contains no usable files.", nil);
    else if (dynamic_cast <const ElevationFailed *> (&e))
        desc = NSLocalizedString (@"Administrator authentication failed.", nil);
    else if (dynamic_cast <const TestFailed *> (&e))
        desc = NSLocalizedString (@"A self-test failed. Do not use this build of Basalt.", nil);

    // --- User abort (cancelled dialog) ---
    else if (dynamic_cast <const UserAbort *> (&e))
        desc = NSLocalizedString (@"Operation cancelled.", nil);

    // --- External process failure (hdiutil, mount_nfs, etc.) ---
    else if (auto *epf = dynamic_cast <const ExecutedProcessFailed *> (&e)) {
        string errOut = epf->GetErrorOutput ();
        if (!errOut.empty ())
            desc = [NSString stringWithFormat:NSLocalizedString (@"%@ failed:\n%@", nil),
                    @(epf->GetCommand ().c_str ()), @(errOut.c_str ())];
        else
            desc = [NSString stringWithFormat:NSLocalizedString (@"%@ failed (exit code %lld).", nil),
                    @(epf->GetCommand ().c_str ()), (long long) epf->GetExitCode ()];
    }

    // --- System exception: include errno text ---
    else if (auto *se = dynamic_cast <const SystemException *> (&e)) {
        wstring sysText = se->SystemText ();
        if (!sysText.empty ())
            desc = [NSString stringWithFormat:NSLocalizedString (@"System error: %@", nil), ToNS (sysText)];
    }

    // --- Invalid parameter: generic text plus the technical detail ---
    else if (dynamic_cast <const ParameterIncorrect *> (&e)) {
        const char *where = e.what ();
        desc = [NSString stringWithFormat:NSLocalizedString (@"The operation could not be completed because of an invalid parameter (%@).", nil),
                where && *where ? @(where) : @"?"];
    }

    // --- Fallback: use what() as-is ---
    if (!desc) {
        const char *msg = e.what ();
        if (msg && *msg)
            desc = [NSString stringWithUTF8String:msg];
        else
            desc = NSLocalizedString (@"An unknown error occurred.", nil);
    }

    return [NSError errorWithDomain:TCErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: desc}];
}

// ---- Helper: Keyfile list conversion ----

static shared_ptr <KeyfileList> ToKeyfileList (NSArray<NSString *> *paths)
{
    if (!paths || paths.count == 0) return nullptr;
    auto kf = make_shared <KeyfileList> ();
    for (NSString *p in paths)
        kf->push_back (make_shared <Keyfile> (ToWide (p)));
    return kf;
}

// ============================================================
#pragma mark - TCVolumeInfo
// ============================================================

@implementation TCVolumeInfo
{
    // Fields stored directly, no C++ member
}

- (instancetype)initWithCppInfo:(shared_ptr <VolumeInfo>)info
{
    self = [super init];
    if (self && info)
    {
        _slotNumber = info->SlotNumber;
        _path = ToNS (wstring (info->Path));
        _mountPoint = ToNS (wstring (info->MountPoint));
        _virtualDevice = ToNS (wstring (info->VirtualDevice));
        _size = info->Size;
        _encryptionAlgorithmName = ToNS (info->EncryptionAlgorithmName);
        _encryptionModeName = ToNS (info->EncryptionModeName);
        _pkcs5PrfName = ToNS (info->Pkcs5PrfName);
        _pkcs5IterationCount = info->Pkcs5IterationCount;
        _isHiddenVolume = (info->Type == Basalt::VolumeType::Hidden);
        _isReadOnly = (info->Protection == Basalt::VolumeProtection::ReadOnly);
        _hiddenVolumeProtectionTriggered = info->HiddenVolumeProtectionTriggered;
        _systemEncryption = info->SystemEncryption;
        _totalDataRead = info->TotalDataRead;
        _totalDataWritten = info->TotalDataWritten;
    }
    return self;
}

@end

// ============================================================
#pragma mark - TCHostDevice
// ============================================================

@implementation TCHostDevice

- (instancetype)initWithCppDevice:(const HostDevice &)dev
{
    self = [super init];
    if (self)
    {
        _path = ToNS (wstring (dev.Path));
        _mountPoint = ToNS (wstring (dev.MountPoint));
        _name = ToNS (dev.Name);
        _size = dev.Size;
        _removable = dev.Removable;

        NSMutableArray *parts = [NSMutableArray array];
        for (const auto &p : dev.Partitions)
        {
            TCHostDevice *part = [[TCHostDevice alloc] initWithCppDevice:*p];
            [parts addObject:part];
        }
        _partitions = [parts copy];
    }
    return self;
}

@end

// ============================================================
#pragma mark - TCMountOptions
// ============================================================

@implementation TCMountOptions

- (instancetype)init
{
    self = [super init];
    if (self)
    {
        _slotNumber = 0;
        _preserveTimestamps = YES;
    }
    return self;
}

- (MountOptions)toCpp
{
    MountOptions opts;

    if (self.volumePath)
        opts.Path = make_shared <VolumePath> (ToWide (self.volumePath));

    if (self.mountPoint)
        opts.MountPoint = make_shared <DirectoryPath> (ToWide (self.mountPoint));

    if (self.password)
        opts.Password = PasswordFromNS (self.password);

    opts.Keyfiles = ToKeyfileList (self.keyfilePaths);

    if (self.slotNumber > 0)
        opts.SlotNumber = (VolumeSlotNumber) self.slotNumber;

    if (self.readOnly)
        opts.Protection = Basalt::VolumeProtection::ReadOnly;

    if (self.protectHiddenVolume)
    {
        opts.Protection = Basalt::VolumeProtection::HiddenVolumeReadOnly;
        if (self.protectionPassword)
            opts.ProtectionPassword = PasswordFromNS (self.protectionPassword);
        opts.ProtectionKeyfiles = ToKeyfileList (self.protectionKeyfilePaths);
    }

    if (self.kdfHint.length > 0)
        opts.KdfHint = ToWide (self.kdfHint);

    opts.UseBackupHeaders = self.useBackupHeaders;
    opts.NoFilesystem = self.noFilesystem;
    opts.PreserveTimestamps = self.preserveTimestamps;
    opts.SharedAccessAllowed = self.sharedAccessAllowed;

    return opts;
}

@end

// ============================================================
#pragma mark - TCVolumeCreationOptions / Progress
// ============================================================

@implementation TCVolumeCreationOptions

- (instancetype)init
{
    self = [super init];
    if (self)
    {
        _volumeType = TCVolumeTypeNormal;
        _filesystem = TCFilesystemTypeMacOsExt;
    }
    return self;
}

@end

@implementation TCVolumeCreationProgress

- (instancetype)initWithInProgress:(BOOL)inProgress total:(uint64_t)total done:(uint64_t)done
{
    self = [super init];
    if (self)
    {
        _inProgress = inProgress;
        _totalSize = total;
        _sizeDone = done;
        _fraction = (total > 0) ? (double)done / (double)total : 0.0;
    }
    return self;
}

@end

// ============================================================
#pragma mark - TCCoreBridge
// ============================================================

@implementation TCCoreBridge
{
    BOOL _initialized;
    shared_ptr <VolumeCreator> _creator;
}

+ (instancetype)shared
{
    static TCCoreBridge *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once (&onceToken, ^{
        instance = [[TCCoreBridge alloc] init];
    });
    return instance;
}

- (instancetype)init
{
    self = [super init];
    if (self)
    {
        _initialized = NO;
    }
    return self;
}

// ---- Lifecycle ----

- (BOOL)initializeCore:(NSError **)error
{
    if (_initialized) return YES;

    try
    {
        // Set executable path for privilege elevation (sudo re-exec)
        NSString *execPath = [[NSBundle mainBundle] executablePath];
        if (execPath)
            Core->SetApplicationExecutablePath (FilePath (ToWide (execPath)));

        // Admin password callback — used when privilege elevation is needed.
        // Uses AskAdminPassword() which displays a Cocoa dialog on the main thread.
        class AdminPasswordFunctor : public GetStringFunctor
        {
        public:
            virtual void operator() (string &str)
            {
                if (!AskAdminPassword (str))
                    throw UserAbort (SRC_POS);
            }
        };

        CoreService::SetAdminPasswordCallback (
            shared_ptr <GetStringFunctor> (new AdminPasswordFunctor));

        // Start the CoreService child process (handles privileged operations via IPC)
        CoreService::Start ();

        Core->Init ();
        _initialized = YES;
        return YES;
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return NO;
    }
}

- (void)shutdownCore
{
    if (!_initialized) return;

    try
    {
        CoreService::Stop ();
    }
    catch (...) { }
}

// ---- Mount / Dismount ----

- (nullable TCVolumeInfo *)mountVolume:(TCMountOptions *)options error:(NSError **)error
{
    try
    {
        MountOptions cppOpts = [options toCpp];

        // The passwords now live in mlock()-ed VolumePassword buffers; drop the
        // NSString references so they are not kept alive by the options object.
        options.password = nil;
        options.protectionPassword = nil;

        // Auto-dismount device filesystems before mounting an encrypted device.
        // The existing filesystem must be unmounted so Basalt can open it exclusively.
#ifdef TC_MACOSX
        if (cppOpts.Path && cppOpts.Path->IsDevice ())
        {
            // Convert raw device path to the whole-disk non-raw path for diskutil.
            // e.g. /dev/rdisk2s1 → /dev/disk2, /dev/rdisk2 → /dev/disk2
            string devPath = StringConverter::ToSingle (wstring (*cppOpts.Path));
            string diskutilPath = devPath;

            // Strip "r" from /dev/rdiskN → /dev/diskN
            size_t rdiskPos = diskutilPath.find ("/dev/rdisk");
            if (rdiskPos == 0)
                diskutilPath = "/dev/disk" + diskutilPath.substr (10);

            // Strip partition suffix (e.g. /dev/disk2s1 → /dev/disk2)
            size_t sPos = diskutilPath.find ('s', strlen ("/dev/disk"));
            if (sPos != string::npos && sPos > strlen ("/dev/disk"))
                diskutilPath = diskutilPath.substr (0, sPos);

            list <string> args;
            args.push_back ("unmountDisk");
            args.push_back ("force");
            args.push_back (diskutilPath);

            try { Process::Execute ("/usr/sbin/diskutil", args); }
            catch (...) { }
        }
#endif

        shared_ptr <VolumeInfo> vol = Core->MountVolume (cppOpts);

        // Offer KDF upgrade for legacy volumes (TrueCrypt iterations, pre-RFC Argon2id)
        [self offerKdfUpgrade:vol options:cppOpts];

        return [[TCVolumeInfo alloc] initWithCppInfo:vol];
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return nil;
    }
}

// Show a 3-button dialog for legacy KDF upgrade:
//   "Upgrade" / "Not Now" / "Never Ask Again"
// If user chooses Upgrade: dismount, re-encrypt header with modern iterations, remount.
//
// Threading: Called from background thread (Swift Task). All UI via dispatch_sync to main.
// The PBKDF2 work runs on the calling (background) thread; a progress window is shown
// on the main thread via performSelectorOnMainThread (no dispatch_sync needed during work).
- (void)offerKdfUpgrade:(shared_ptr <VolumeInfo> &)vol options:(MountOptions &)opts
{
    if (!vol)
        return;

    // Legacy KDFs: TrueCrypt iteration counts and the non-standard Argon2id of
    // Basalt <= 1.1.x. Everything else needs no upgrade.
    shared_ptr <Pkcs5Kdf> newKdf;
    try { newKdf = Pkcs5Kdf::GetUpgradeTarget (vol->Pkcs5PrfName, (int) vol->Pkcs5IterationCount); }
    catch (...) { return; }

    if (!newKdf)
        return;

    if (!opts.Password || opts.Password->IsEmpty ())
        return;

    // Check "Never Ask Again" preference
    if ([[NSUserDefaults standardUserDefaults] boolForKey:@"suppressKdfUpgradePrompt"])
        return;

    bool argon2Migration = vol->Pkcs5PrfName.find (L"Argon2id") == 0;

    NSString *currentIter = [NSString stringWithFormat:@"%u", (unsigned) vol->Pkcs5IterationCount];
    NSString *modernIter = [NSString stringWithFormat:@"%u", (unsigned) newKdf->GetIterationCount ()];
    NSString *hashName = ToNS (vol->Pkcs5PrfName);
    NSString *newKdfName = ToNS (newKdf->GetName ());

    NSString *message;
    if (argon2Migration)
    {
        message = [NSString stringWithFormat:
            NSLocalizedString (@"This volume header was created by Basalt 1.1 or earlier (%@). Those versions used an Argon2id implementation that deviates from the RFC 9106 standard.\n\nUpgrading re-encrypts the volume header with standard %@. Your data, password, and encryption remain unchanged.", nil),
            hashName, newKdfName];
    }
    else
    {
        message = [NSString stringWithFormat:
            NSLocalizedString (@"This volume uses legacy key derivation (%@, %@ iterations).\n\nModern volumes use %@ iterations — this makes brute-force attacks against your password significantly harder.\n\nUpgrading re-encrypts the volume header with stronger key derivation. Your data, password, and encryption remain unchanged.\n\n⚠ After upgrading, the volume can no longer be opened by TrueCrypt 7.1a. If you are unsure, choose \"Not Now\".", nil),
            hashName, currentIter, modernIter];
    }

    // Show 3-button dialog on main thread
    __block NSInteger choice = 1; // default: Not Now

    dispatch_block_t dialogBlock = ^{
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = NSLocalizedString (@"Upgrade Volume Key Derivation?", nil);
        alert.informativeText = message;
        alert.alertStyle = NSAlertStyleInformational;
        [alert addButtonWithTitle:NSLocalizedString (@"Upgrade", nil)];
        [alert addButtonWithTitle:NSLocalizedString (@"Not Now", nil)];
        [alert addButtonWithTitle:NSLocalizedString (@"Never Ask Again", nil)];

        NSModalResponse resp = [alert runModal];
        choice = resp - NSAlertFirstButtonReturn;
    };

    if ([NSThread isMainThread])
        dialogBlock ();
    else
        dispatch_sync (dispatch_get_main_queue (), dialogBlock);

    if (choice == 2) // Never Ask Again
    {
        [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@"suppressKdfUpgradePrompt"];
        return;
    }

    if (choice != 0) // Not "Upgrade"
        return;

    // Perform the upgrade on this (background) thread.
    // Update the loading status so MountSheet shows progress.
    auto postStatus = [] (NSString *status) {
        dispatch_async (dispatch_get_main_queue (), ^{
            [[NSNotificationCenter defaultCenter]
                postNotificationName:@"TCLoadingStatusChanged"
                object:nil
                userInfo:@{@"status": status}];
        });
    };

    try
    {
        postStatus (NSLocalizedString (@"Upgrading volume header...", nil));

        RandomNumberGenerator::Start ();
        RandomNumberGenerator::SetHash (newKdf->GetHash ());

        // Dismount so the volume file is not locked by FUSE
        Core->DismountVolume (vol);
        vol.reset ();

        // wipePassCount=1: same master key, no old key material to erase
        Core->ChangePassword (
            make_shared <VolumePath> (*opts.Path),
            opts.PreserveTimestamps,
            opts.Password, opts.Keyfiles,
            opts.Password, opts.Keyfiles,
            newKdf, 1);

        // Remount the upgraded volume
        postStatus (NSLocalizedString (@"Remounting...", nil));
        vol = Core->MountVolume (opts);

        // Show success
        NSString *successMsg = argon2Migration
            ? [NSString stringWithFormat:
                NSLocalizedString (@"Volume header upgraded successfully.\nNew key derivation: %@", nil), newKdfName]
            : [NSString stringWithFormat:
                NSLocalizedString (@"Volume header upgraded successfully.\nNew iterations: %@", nil), modernIter];

        dispatch_block_t infoBlock = ^{
            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = successMsg;
            alert.alertStyle = NSAlertStyleInformational;
            [alert addButtonWithTitle:NSLocalizedString (@"OK", nil)];
            [alert runModal];
        };

        if ([NSThread isMainThread])
            infoBlock ();
        else
            dispatch_sync (dispatch_get_main_queue (), infoBlock);
    }
    catch (exception &e)
    {
        NSString *errMsg = [NSString stringWithFormat:NSLocalizedString (@"Header upgrade failed: %@", nil), ExceptionToError (e).localizedDescription];

        dispatch_block_t errBlock = ^{
            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = errMsg;
            alert.alertStyle = NSAlertStyleWarning;
            [alert addButtonWithTitle:NSLocalizedString (@"OK", nil)];
            [alert runModal];
        };

        if ([NSThread isMainThread])
            errBlock ();
        else
            dispatch_sync (dispatch_get_main_queue (), errBlock);
    }
}

- (BOOL)dismountVolume:(TCVolumeInfo *)volume force:(BOOL)force error:(NSError **)error
{
    try
    {
        // Find the volume by slot number
        shared_ptr <VolumeInfo> vol = Core->GetMountedVolume ((VolumeSlotNumber) volume.slotNumber);
        if (!vol)
        {
            if (error) *error = [NSError errorWithDomain:TCErrorDomain code:-1
                userInfo:@{NSLocalizedDescriptionKey: NSLocalizedString (@"Volume not found", nil)}];
            return NO;
        }
        Core->DismountVolume (vol, force);
        return YES;
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return NO;
    }
}

- (BOOL)dismountAllVolumes:(BOOL)force error:(NSError **)error
{
    try
    {
        VolumeInfoList volumes = Core->GetMountedVolumes ();
        for (const auto &vol : volumes)
            Core->DismountVolume (vol, force);
        return YES;
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return NO;
    }
}

- (BOOL)isVolumeMounted:(NSString *)path
{
    try
    {
        return Core->IsVolumeMounted (VolumePath (ToWide (path)));
    }
    catch (...)
    {
        return NO;
    }
}

// ---- Volume Queries ----

- (NSArray<TCVolumeInfo *> *)mountedVolumes
{
    try
    {
        VolumeInfoList vols = Core->GetMountedVolumes ();
        NSMutableArray *result = [NSMutableArray arrayWithCapacity:vols.size ()];
        for (const auto &v : vols)
            [result addObject:[[TCVolumeInfo alloc] initWithCppInfo:v]];
        return [result copy];
    }
    catch (...)
    {
        return @[];
    }
}

// ---- Host Devices ----

- (NSArray<TCHostDevice *> *)hostDevices:(NSError **)error
{
    try
    {
        HostDeviceList devices = Core->GetHostDevices ();
        NSMutableArray *result = [NSMutableArray arrayWithCapacity:devices.size ()];
        for (const auto &d : devices)
            [result addObject:[[TCHostDevice alloc] initWithCppDevice:*d]];
        return [result copy];
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return @[];
    }
}

// ---- Change Password ----

- (BOOL)changePasswordForVolume:(NSString *)volumePath
                       password:(NSString *)currentPassword
                       keyfiles:(nullable NSArray<NSString *> *)keyfilePaths
                    newPassword:(NSString *)newPassword
                    newKeyfiles:(nullable NSArray<NSString *> *)newKeyfilePaths
                        newHash:(nullable NSString *)hashName
                          error:(NSError **)error
{
    try
    {
        auto path = make_shared <VolumePath> (ToWide (volumePath));
        auto pw = PasswordFromNS (currentPassword);
        auto kf = ToKeyfileList (keyfilePaths);
        auto newPw = PasswordFromNS (newPassword);
        auto newKf = ToKeyfileList (newKeyfilePaths);

        shared_ptr <Pkcs5Kdf> newKdf;
        if (hashName)
        {
            for (const auto &h : Basalt::Hash::GetAvailableAlgorithms ())
            {
                if ([ToNS (h->GetName ()) caseInsensitiveCompare:hashName] == NSOrderedSame)
                {
                    newKdf = Pkcs5Kdf::GetAlgorithm (*h);
                    break;
                }
            }
        }

        RandomNumberGenerator::Start ();
        Core->ChangePassword (path, true, pw, kf, newPw, newKf, newKdf);
        return YES;
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return NO;
    }
}

// ---- Keyfile Creation ----

- (BOOL)createKeyfile:(NSString *)path error:(NSError **)error
{
    try
    {
        Core->CreateKeyfile (FilePath (ToWide (path)));
        return YES;
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return NO;
    }
}

// ---- Self-Test ----

- (BOOL)runSelfTest:(NSError **)error
{
    try
    {
        EncryptionTest::TestAll ();
        PlatformTest::TestAll ();
        return YES;
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return NO;
    }
}

// ---- Available Algorithms ----

- (NSArray<NSString *> *)availableEncryptionAlgorithms
{
    NSMutableArray *result = [NSMutableArray array];
    for (const auto &ea : Basalt::EncryptionAlgorithm::GetAvailableAlgorithms ())
    {
        if (!ea->IsDeprecated ())
            [result addObject:ToNS (ea->GetName ())];
    }
    return [result copy];
}

- (NSArray<NSString *> *)availableHashAlgorithms
{
    NSMutableArray *result = [NSMutableArray array];
    for (const auto &h : Basalt::Hash::GetAvailableAlgorithms ())
    {
        if (!h->IsDeprecated ())
            [result addObject:ToNS (h->GetName ())];
    }
    return [result copy];
}

// ---- User Entropy ----

- (void)addUserEntropy:(NSData *)data
{
    if (data.length == 0) return;
    if (!RandomNumberGenerator::IsRunning ())
        RandomNumberGenerator::Start ();
    RandomNumberGenerator::AddToPool (ConstBufferPtr (
        reinterpret_cast <const byte *> (data.bytes), data.length));
}

// ---- Volume Creation ----

- (BOOL)startVolumeCreation:(TCVolumeCreationOptions *)options error:(NSError **)error
{
    try
    {
        auto cppOpts = make_shared <VolumeCreationOptions> ();
        cppOpts->Path = VolumePath (ToWide (options.path));
        cppOpts->Type = (options.volumeType == TCVolumeTypeHidden) ? Basalt::VolumeType::Hidden : Basalt::VolumeType::Normal;
        cppOpts->Size = options.size;

        if (options.password)
            cppOpts->Password = PasswordFromNS (options.password);

        cppOpts->Keyfiles = ToKeyfileList (options.keyfilePaths);
        cppOpts->Quick = options.quickFormat;
        cppOpts->FilesystemClusterSize = 0;  // 0 = auto-detect optimal cluster size

        switch (options.filesystem)
        {
        case TCFilesystemTypeNone:
            cppOpts->Filesystem = VolumeCreationOptions::FilesystemType::None;
            break;
        case TCFilesystemTypeFAT:
            cppOpts->Filesystem = VolumeCreationOptions::FilesystemType::FAT;
            break;
        case TCFilesystemTypeMacOsExt:
            cppOpts->Filesystem = VolumeCreationOptions::FilesystemType::MacOsExt;
            break;
        }

        // Encryption algorithm
        if (options.encryptionAlgorithm)
        {
            for (const auto &ea : Basalt::EncryptionAlgorithm::GetAvailableAlgorithms ())
            {
                if (!ea->IsDeprecated () && [ToNS (ea->GetName ()) caseInsensitiveCompare:options.encryptionAlgorithm] == NSOrderedSame)
                {
                    cppOpts->EA = ea;
                    break;
                }
            }
        }

        // Hash / KDF
        if (options.hashAlgorithm)
        {
            for (const auto &h : Basalt::Hash::GetAvailableAlgorithms ())
            {
                if (!h->IsDeprecated () && [ToNS (h->GetName ()) caseInsensitiveCompare:options.hashAlgorithm] == NSOrderedSame)
                {
                    // Argon2id variants have no legacy — force legacy=false
                    bool legacy = options.legacyIterations;
                    if (h->GetName ().find(L"Argon2id") != std::wstring::npos) legacy = false;
                    cppOpts->VolumeHeaderKdf = Pkcs5Kdf::GetAlgorithm (*h, legacy);
                    RandomNumberGenerator::SetHash (h);
                    break;
                }
            }
        }

        if (!cppOpts->VolumeHeaderKdf)
        {
            if (error) *error = [NSError errorWithDomain:@"Basalt" code:-1
                userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:NSLocalizedString (@"Unknown hash algorithm: %@", nil), options.hashAlgorithm]}];
            return NO;
        }

        RandomNumberGenerator::Start ();

        // Auto-dismount device filesystems before creation.
        // A mounted device cannot be opened exclusively — unmount all its
        // partitions first (like TrueCrypt/VeraCrypt do).
#ifdef TC_MACOSX
        if (cppOpts->Path.IsDevice ())
        {
            // Convert raw device path to the whole-disk non-raw path for diskutil.
            // e.g. /dev/rdisk2s1 → /dev/disk2, /dev/rdisk2 → /dev/disk2
            string devPath = StringConverter::ToSingle (wstring (cppOpts->Path));
            string diskutilPath = devPath;

            // Strip "r" from /dev/rdiskN → /dev/diskN
            size_t rdiskPos = diskutilPath.find ("/dev/rdisk");
            if (rdiskPos == 0)
                diskutilPath = "/dev/disk" + diskutilPath.substr (10);

            // Strip partition suffix (e.g. /dev/disk2s1 → /dev/disk2)
            size_t sPos = diskutilPath.find ('s', strlen ("/dev/disk"));
            if (sPos != string::npos && sPos > strlen ("/dev/disk"))
                diskutilPath = diskutilPath.substr (0, sPos);

            list <string> args;
            args.push_back ("unmountDisk");
            args.push_back ("force");
            args.push_back (diskutilPath);

            try { Process::Execute ("/usr/sbin/diskutil", args); }
            catch (...) { /* best effort — creation will fail with EBUSY if still mounted */ }
        }
#endif

        _creator = make_shared <VolumeCreator> ();
        _creator->CreateVolume (cppOpts);
        return YES;
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return NO;
    }
}

- (TCVolumeCreationProgress *)volumeCreationProgress
{
    if (!_creator) return [[TCVolumeCreationProgress alloc] initWithInProgress:NO total:0 done:0];

    VolumeCreator::ProgressInfo pi = _creator->GetProgressInfo ();
    return [[TCVolumeCreationProgress alloc] initWithInProgress:pi.CreationInProgress
                                                          total:pi.TotalSize
                                                           done:pi.SizeDone];
}

- (void)abortVolumeCreation
{
    if (_creator)
        _creator->Abort ();
}

- (BOOL)formatVolumeFilesystem:(NSString *)volumePath
                      password:(NSString *)password
                      keyfiles:(nullable NSArray<NSString *> *)keyfilePaths
                    filesystem:(TCFilesystemType)filesystem
                         error:(NSError **)error
{
    if (filesystem != TCFilesystemTypeMacOsExt)
        return YES; // Only HFS+ needs post-creation formatting

    try
    {
        // 1. Mount the volume without filesystem (NoFilesystem = true)
        MountOptions opts;
        opts.Path = make_shared <VolumePath> (ToWide (volumePath));
        opts.Password = PasswordFromNS (password);
        opts.Keyfiles = ToKeyfileList (keyfilePaths);
        opts.NoFilesystem = true;

        shared_ptr <VolumeInfo> vol = Core->MountVolume (opts);
        if (!vol)
            throw ParameterIncorrect (SRC_POS);

        // 2. Get the virtual block device (e.g. /dev/disk4) that hdiutil attached
        string virtualDev = vol->VirtualDevice;
        if (virtualDev.empty ())
            throw ParameterIncorrect (SRC_POS);

        // 3. Format the virtual device with HFS+.
        //    Use diskutil instead of newfs_hfs because the latter requires
        //    root privileges on the block device while diskutil handles
        //    authorization itself.  Retry a few times in case hdiutil has
        //    not finished configuring the device node yet.
        list <string> args;
        args.push_back ("eraseVolume");
        args.push_back ("HFS+");
        args.push_back ("Basalt");
        args.push_back (virtualDev);

        try
        {
            int retries = 5;
            while (true)
            {
                try
                {
                    Process::Execute ("/usr/sbin/diskutil", args);
                    break;
                }
                catch (...)
                {
                    if (--retries <= 0)
                        throw;
                    Thread::Sleep (500);
                }
            }

            // diskutil eraseVolume auto-mounts the new filesystem (e.g. on
            // /Volumes/Basalt).  Unmount it before we dismount the Basalt
            // FUSE volume, otherwise hdiutil detach will fail with EBUSY.
            list <string> umArgs;
            umArgs.push_back ("unmount");
            umArgs.push_back ("force");
            umArgs.push_back (virtualDev);
            try { Process::Execute ("/usr/sbin/diskutil", umArgs); }
            catch (...) { }
        }
        catch (...)
        {
            // Dismount even if formatting fails
            try { Core->DismountVolume (vol, true); } catch (...) { }
            throw;
        }

        // 4. Dismount the volume
        Core->DismountVolume (vol, true);

        return YES;
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return NO;
    }
}

// ---- Volume Header Backup ----

- (BOOL)backupVolumeHeaders:(NSString *)volumePath
                   password:(NSString *)password
                   keyfiles:(nullable NSArray<NSString *> *)keyfilePaths
             hiddenPassword:(nullable NSString *)hiddenPassword
             hiddenKeyfiles:(nullable NSArray<NSString *> *)hiddenKeyfilePaths
               backupToFile:(NSString *)backupFilePath
                      error:(NSError **)error
{
    try
    {
        auto path = make_shared <VolumePath> (ToWide (volumePath));
        auto pw = PasswordFromNS (password);
        auto kf = ToKeyfileList (keyfilePaths);

#ifdef TC_UNIX
        // Temporarily take ownership of a device if the user is not an administrator
        UserId origDeviceOwner ((uid_t) -1);

        if (!Core->HasAdminPrivileges () && path->IsDevice ())
        {
            origDeviceOwner = FilesystemPath (wstring (*path)).GetOwner ();
            Core->SetFileOwner (*path, UserId (getuid ()));
        }

        finally_do_arg2 (FilesystemPath, *path, UserId, origDeviceOwner,
        {
            if (finally_arg2.SystemId != (uid_t) -1)
                Core->SetFileOwner (finally_arg, finally_arg2);
        });
#endif

        // Open normal volume
        shared_ptr <Volume> normalVolume = Core->OpenVolume (
            path,
            true, // preserveTimestamps
            pw,
            kf,
            VolumeProtection::None,
            shared_ptr <VolumePassword> (),
            shared_ptr <KeyfileList> (),
            true, // sharedAccessAllowed
            Basalt::VolumeType::Normal,
            false  // useBackupHeaders
        );

        // Open hidden volume if credentials provided
        shared_ptr <Volume> hiddenVolume;
        shared_ptr <VolumePassword> hidPw;
        shared_ptr <KeyfileList> hidKf;

        if (hiddenPassword)
        {
            hidPw = PasswordFromNS (hiddenPassword);
            hidKf = ToKeyfileList (hiddenKeyfilePaths);

            hiddenVolume = Core->OpenVolume (
                path,
                true,
                hidPw,
                hidKf,
                VolumeProtection::None,
                shared_ptr <VolumePassword> (),
                shared_ptr <KeyfileList> (),
                true,
                Basalt::VolumeType::Hidden,
                false
            );
        }

        // Verify layout compatibility
        if (hiddenVolume)
        {
            if (typeid (*normalVolume->GetLayout()) == typeid (VolumeLayoutV1Normal) && typeid (*hiddenVolume->GetLayout()) != typeid (VolumeLayoutV1Hidden))
                throw ParameterIncorrect (SRC_POS);

            if (typeid (*normalVolume->GetLayout()) == typeid (VolumeLayoutV2Normal) && typeid (*hiddenVolume->GetLayout()) != typeid (VolumeLayoutV2Hidden))
                throw ParameterIncorrect (SRC_POS);
        }

        File backupFile;
        backupFile.Open (FilePath (ToWide (backupFilePath)), File::CreateWrite);

        RandomNumberGenerator::Start ();

        // Re-encrypt normal volume header with new salt
        SecureBuffer newHeaderBuffer (normalVolume->GetLayout()->GetHeaderSize());
        Core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, normalVolume->GetHeader(), pw, kf);
        backupFile.Write (newHeaderBuffer);

        if (hiddenVolume)
        {
            // Re-encrypt hidden volume header
            Core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, hiddenVolume->GetHeader(), hidPw, hidKf);
        }
        else
        {
            // Store random data in place of hidden volume header
            shared_ptr <Basalt::EncryptionAlgorithm> ea = normalVolume->GetEncryptionAlgorithm ();
            Core->RandomizeEncryptionAlgorithmKey (ea);
            ea->Encrypt (newHeaderBuffer.GetRange (0, newHeaderBuffer.Size ()));
        }

        backupFile.Write (newHeaderBuffer);

        return YES;
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return NO;
    }
}

// ---- Volume Header Restore (Internal Backup) ----

- (BOOL)restoreVolumeHeadersFromInternalBackup:(NSString *)volumePath
                                      password:(NSString *)password
                                      keyfiles:(nullable NSArray<NSString *> *)keyfilePaths
                                         error:(NSError **)error
{
    try
    {
        auto path = make_shared <VolumePath> (ToWide (volumePath));
        auto pw = PasswordFromNS (password);
        auto kf = ToKeyfileList (keyfilePaths);

#ifdef TC_UNIX
        UserId origDeviceOwner ((uid_t) -1);

        if (!Core->HasAdminPrivileges () && path->IsDevice ())
        {
            origDeviceOwner = FilesystemPath (wstring (*path)).GetOwner ();
            Core->SetFileOwner (*path, UserId (getuid ()));
        }

        finally_do_arg2 (FilesystemPath, *path, UserId, origDeviceOwner,
        {
            if (finally_arg2.SystemId != (uid_t) -1)
                Core->SetFileOwner (finally_arg, finally_arg2);
        });
#endif

        // Open volume using backup headers
        shared_ptr <Volume> volume = Core->OpenVolume (
            path,
            true, // preserveTimestamps
            pw,
            kf,
            VolumeProtection::None,
            shared_ptr <VolumePassword> (),
            shared_ptr <KeyfileList> (),
            false, // sharedAccessAllowed
            Basalt::VolumeType::Unknown,
            true   // useBackupHeaders
        );

        shared_ptr <VolumeLayout> layout = volume->GetLayout ();
        if (typeid (*layout) == typeid (VolumeLayoutV1Normal) || typeid (*layout) == typeid (VolumeLayoutV1Hidden))
        {
            if (error)
                *error = [NSError errorWithDomain:TCErrorDomain code:-1
                    userInfo:@{NSLocalizedDescriptionKey: NSLocalizedString (@"This volume format does not contain a backup header.", nil)}];
            return NO;
        }

        RandomNumberGenerator::Start ();

        // Re-encrypt volume header with new salt
        SecureBuffer newHeaderBuffer (layout->GetHeaderSize());
        Core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, volume->GetHeader(), pw, kf);

        // Write to primary header location
        int headerOffset = layout->GetHeaderOffset ();
        shared_ptr <File> volumeFile = volume->GetFile ();

        if (headerOffset >= 0)
            volumeFile->SeekAt (headerOffset);
        else
            volumeFile->SeekEnd (headerOffset);

        volumeFile->Write (newHeaderBuffer);

        return YES;
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return NO;
    }
}

// ---- Volume Header Restore (External Backup File) ----

- (BOOL)restoreVolumeHeadersFromFile:(NSString *)volumePath
                          backupFile:(NSString *)backupFilePath
                            password:(NSString *)password
                            keyfiles:(nullable NSArray<NSString *> *)keyfilePaths
                               error:(NSError **)error
{
    try
    {
        auto path = make_shared <VolumePath> (ToWide (volumePath));
        auto pw = PasswordFromNS (password);
        auto kf = ToKeyfileList (keyfilePaths);

#ifdef TC_UNIX
        UserId origDeviceOwner ((uid_t) -1);

        if (!Core->HasAdminPrivileges () && path->IsDevice ())
        {
            origDeviceOwner = FilesystemPath (wstring (*path)).GetOwner ();
            Core->SetFileOwner (*path, UserId (getuid ()));
        }

        finally_do_arg2 (FilesystemPath, *path, UserId, origDeviceOwner,
        {
            if (finally_arg2.SystemId != (uid_t) -1)
                Core->SetFileOwner (finally_arg, finally_arg2);
        });
#endif

        File backupFileObj;
        backupFileObj.Open (FilePath (ToWide (backupFilePath)), File::OpenRead);

        bool legacyBackup;
        switch (backupFileObj.Length ())
        {
        case TC_VOLUME_HEADER_GROUP_SIZE:
            legacyBackup = false;
            break;

        case TC_VOLUME_HEADER_SIZE_LEGACY * 2:
            legacyBackup = true;
            break;

        default:
            if (error)
                *error = [NSError errorWithDomain:TCErrorDomain code:-1
                    userInfo:@{NSLocalizedDescriptionKey: NSLocalizedString (@"The backup file size is incorrect. This may not be a valid volume header backup.", nil)}];
            return NO;
        }

        // Decrypt the backup header
        shared_ptr <VolumeLayout> decryptedLayout;
        shared_ptr <VolumePassword> passwordKey = Keyfile::ApplyListToPassword (kf, pw);

        for (const auto &layout : VolumeLayout::GetAvailableLayouts ())
        {
            if (layout->HasDriveHeader ())
                continue;

            if (!legacyBackup && (typeid (*layout) == typeid (VolumeLayoutV1Normal) || typeid (*layout) == typeid (VolumeLayoutV1Hidden)))
                continue;

            if (legacyBackup && (typeid (*layout) == typeid (VolumeLayoutV2Normal) || typeid (*layout) == typeid (VolumeLayoutV2Hidden)))
                continue;

            SecureBuffer headerBuffer (layout->GetHeaderSize ());
            backupFileObj.ReadAt (headerBuffer, layout->GetType () == Basalt::VolumeType::Hidden ? layout->GetHeaderSize () : 0);

            if (layout->GetHeader ()->Decrypt (headerBuffer, *passwordKey, layout->GetSupportedKeyDerivationFunctions (), layout->GetSupportedEncryptionAlgorithms (), layout->GetSupportedEncryptionModes ()))
            {
                decryptedLayout = layout;
                break;
            }
        }

        if (!decryptedLayout)
            throw PasswordIncorrect (SRC_POS);

        File volumeFile;
        volumeFile.Open (*path, File::OpenReadWrite, File::ShareNone, File::PreserveTimestamps);

        RandomNumberGenerator::Start ();

        // Re-encrypt and write primary header
        SecureBuffer newHeaderBuffer (decryptedLayout->GetHeaderSize ());
        Core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, decryptedLayout->GetHeader (), pw, kf);

        int headerOffset = decryptedLayout->GetHeaderOffset ();
        if (headerOffset >= 0)
            volumeFile.SeekAt (headerOffset);
        else
            volumeFile.SeekEnd (headerOffset);

        volumeFile.Write (newHeaderBuffer);

        // Write backup header too if the layout supports it
        if (decryptedLayout->HasBackupHeader ())
        {
            Core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, decryptedLayout->GetHeader (), pw, kf);

            headerOffset = decryptedLayout->GetBackupHeaderOffset ();
            if (headerOffset >= 0)
                volumeFile.SeekAt (headerOffset);
            else
                volumeFile.SeekEnd (headerOffset);

            volumeFile.Write (newHeaderBuffer);
        }

        return YES;
    }
    catch (const std::exception &e)
    {
        if (error) *error = ExceptionToError (e);
        return NO;
    }
}

@end

// ---- Elevated service entry point ----

extern "C" BOOL TCHandleCoreServiceArgument (int argc, char * _Nullable * _Nonnull argv)
{
    if (argc < 2 || strcmp (argv[1], TC_CORE_SERVICE_CMDLINE_OPTION) != 0)
        return NO;

    try
    {
        CoreService::ProcessElevatedRequests ();
    }
    catch (...) { }
    return YES;
}
