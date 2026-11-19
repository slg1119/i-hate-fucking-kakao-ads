import Foundation

enum EngineTests {
    static func check(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
        guard try condition() else { throw PatchFailure.message(message) }
        print("PASS: \(message)")
    }
    static func run(sourcePath: String? = nil, legacySourcePath: String? = nil) throws {
        let fm = FileManager.default
        setbuf(stdout,nil)
        let installed = URL(fileURLWithPath:"/Applications/KakaoTalk.app")
        let installedHash = try PatchSpec.hashFile(installed.appendingPathComponent("Contents/MacOS/KakaoTalk"))
        let root = fm.temporaryDirectory.appendingPathComponent("NoAdKakao-QA-"+UUID().uuidString)
        try fm.createDirectory(at:root,withIntermediateDirectories:true)
        defer { try? fm.removeItem(at:root) }
        let app = root.appendingPathComponent("KakaoTalk.app")
        let engine = PatchEngine(backupRoot:root.appendingPathComponent("Backups"),allowAdministrator:false,progress:{ print($0) })
        var source = sourcePath.map { URL(fileURLWithPath:$0).standardizedFileURL } ?? installed
        if sourcePath == nil && PatchSpec.profile(for: installedHash) == nil {
            source = PatchEngine().backupDirectory(installed).appendingPathComponent("Original.backup")
        }
        guard let profile = PatchSpec.profile(for: try PatchSpec.hashFile(source.appendingPathComponent("Contents/MacOS/KakaoTalk"))) else { throw PatchFailure.message("통합 테스트에는 분석된 원본 앱 또는 검증된 원본 백업이 필요합니다.") }
        try engine.copy(source,app)
        if let legacySourcePath {
            guard profile.originalHash != PatchSpec.legacy.originalHash else { throw PatchFailure.message("업그레이드 테스트에는 새 버전 원본이 필요합니다.") }
            let legacySource = URL(fileURLWithPath:legacySourcePath).standardizedFileURL
            guard try PatchSpec.hashFile(engine.binary(legacySource)) == PatchSpec.legacy.originalHash else { throw PatchFailure.message("기존 백업 원본이 지원 버전과 다릅니다.") }
            let oldDir = engine.backupDirectory(app)
            try fm.createDirectory(at:oldDir,withIntermediateDirectories:true)
            let oldBackup = oldDir.appendingPathComponent("Original.backup")
            try engine.copy(legacySource,oldBackup)
            let oldRecord = BackupRecord(schema:1,targetPath:app.path,originalHash:PatchSpec.legacy.originalHash,createdAt:Date(),inventory:try engine.inventory(oldBackup),installedHash:"historical-signed-hash")
            try engine.saveRecord(oldRecord,app)
        }
        try check(engine.inspect(app).state == .ready,"exact supported build detected")
        let before = try engine.inventory(app)
        do { _ = try PatchSpec.patch(Data("wrong build".utf8)); throw PatchFailure.message("version guard failed") }
        catch { try check(error.localizedDescription.contains("빌드"),"unrelated build rejected") }
        do { try engine.apply(app); throw PatchFailure.message("consent guard failed") }
        catch { try check(error.localizedDescription.contains("예외"),"explicit exception consent required") }
        do { try engine.apply(app,allowLibraryValidationException:true,simulateFailure:true); throw PatchFailure.message("failure injection did not run") }
        catch { print("Staging outcome: \(error.localizedDescription)"); try check(error.localizedDescription.contains("설치 직전"),"staged failure reported") }
        try check(try engine.inventory(app) == before,"failed preparation leaves installed app byte-identical")
        try engine.apply(app,allowLibraryValidationException:true)
        try check(engine.inspect(app).state == .applied,"apply replaces the app at its existing path")
        try check(engine.hasLibraryException(app),"ad-hoc hardened app carries the required library validation exception")
        let signed = try Data(contentsOf:engine.binary(app))
        guard let arm = try MachO.slices(signed).first(where: { $0.cpu == 0x0100000c }) else { throw PatchFailure.message("테스트 arm64 슬라이스 없음") }
        for site in profile.sites {
            try check(signed.subdata(in:arm.offset+site.offset..<arm.offset+site.offset+site.replacement.count) == site.replacement, "signed patch site \(String(site.offset,radix:16)) verified")
        }
        try engine.run("/usr/bin/codesign",["--verify","--deep","--strict",app.path])
        try check(fm.fileExists(atPath:app.path),"patched app passes deep signature verification")
        // Reproduce the older GUI's signed-but-unlaunchable configuration.
        let legacyEnt = root.appendingPathComponent("legacy-entitlements.plist")
        guard let currentEnt = try MachO.entitlements(engine.binary(app)),
              var legacy = try PropertyListSerialization.propertyList(from:currentEnt,format:nil) as? [String:Any] else { throw PatchFailure.message("테스트 권한 정보 없음") }
        legacy.removeValue(forKey:"com.apple.security.cs.disable-library-validation")
        try PropertyListSerialization.data(fromPropertyList:legacy,format:.xml,options:0).write(to:legacyEnt)
        try engine.run("/usr/bin/codesign",["--force","--sign","-","--options","runtime","--entitlements",legacyEnt.path,"--generate-entitlement-der",app.path])
        var legacyRecord = try engine.loadRecord(app,profile:profile); legacyRecord.installedHash = try PatchSpec.hashFile(engine.binary(app)); try engine.saveRecord(legacyRecord,app,profile:profile)
        try check(engine.inspect(app).state == .needsRepair,"legacy library-validation failure detected before launch")
        try engine.repair(app,allowLibraryValidationException:true)
        try check(engine.inspect(app).state == .applied && engine.hasLibraryException(app),"repair rebuilds from original backup with corrected entitlements")
        let backup = engine.backupDirectory(app,profile:profile).appendingPathComponent("Original.backup/Contents/Info.plist")
        let originalInfo = try Data(contentsOf:backup)
        try Data("tampered".utf8).write(to:backup)
        let fixtureHash = try PatchSpec.hashFile(engine.binary(app))
        do { try engine.restore(app); throw PatchFailure.message("corrupted backup accepted") }
        catch { try check(error.localizedDescription.contains("백업이 변경"),"tampered backup rejected") }
        try check(try PatchSpec.hashFile(engine.binary(app)) == fixtureHash,"rejected restore preserves current app")
        try originalInfo.write(to:backup)
        try engine.restore(app)
        try check(try engine.inventory(app) == before,"restore reproduces every original file and symbolic link")
        try check(engine.inspect(app).state == .ready,"restored app is detected as original")
        if legacySourcePath != nil {
            let old = try engine.loadRecord(app)
            try check(old.originalHash == PatchSpec.legacy.originalHash && old.installedHash == "historical-signed-hash", "historical backup record preserved across upgrade")
            try check(try engine.inventory(engine.backupDirectory(app).appendingPathComponent("Original.backup")) == old.inventory, "historical backup contents preserved across upgrade")
            try check(try PatchSpec.hashFile(engine.binary(app)) == profile.originalHash, "upgrade restore selects current version, not historical backup")
        }
        try check(try PatchSpec.hashFile(engine.binary(installed)) == installedHash,"real installed app remains unchanged during tests")
        print("ALL ENGINE INTEGRATION TESTS PASSED")
    }
}
