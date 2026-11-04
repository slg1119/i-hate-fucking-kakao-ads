import Foundation

enum EngineTests {
    static func check(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
        guard try condition() else { throw PatchFailure.message(message) }
        print("PASS: \(message)")
    }
    static func run() throws {
        let fm = FileManager.default
        setbuf(stdout,nil)
        let installed = URL(fileURLWithPath:"/Applications/KakaoTalk.app")
        let installedHash = try PatchSpec.hashFile(installed.appendingPathComponent("Contents/MacOS/KakaoTalk"))
        let root = fm.temporaryDirectory.appendingPathComponent("NoAdKakao-QA-"+UUID().uuidString)
        try fm.createDirectory(at:root,withIntermediateDirectories:true)
        defer { try? fm.removeItem(at:root) }
        let app = root.appendingPathComponent("KakaoTalk.app")
        let engine = PatchEngine(backupRoot:root.appendingPathComponent("Backups"),allowAdministrator:false,progress:{ print($0) })
        var source = installed
        if installedHash != PatchSpec.originalHash {
            source = PatchEngine().backupDirectory(installed).appendingPathComponent("Original.backup")
        }
        guard try PatchSpec.hashFile(source.appendingPathComponent("Contents/MacOS/KakaoTalk")) == PatchSpec.originalHash else { throw PatchFailure.message("통합 테스트에는 분석된 원본 앱 또는 검증된 원본 백업이 필요합니다.") }
        try engine.copy(source,app)
        try check(engine.inspect(app).state == .ready,"exact supported build detected")
        let before = try engine.inventory(app)
        do { _ = try PatchSpec.patch(Data("wrong build".utf8)); throw PatchFailure.message("version guard failed") }
        catch { try check(error.localizedDescription.contains("26.9.0"),"unrelated build rejected") }
        do { try engine.apply(app); throw PatchFailure.message("consent guard failed") }
        catch { try check(error.localizedDescription.contains("예외"),"explicit exception consent required") }
        do { try engine.apply(app,allowLibraryValidationException:true,simulateFailure:true); throw PatchFailure.message("failure injection did not run") }
        catch { print("Staging outcome: \(error.localizedDescription)"); try check(error.localizedDescription.contains("설치 직전"),"staged failure reported") }
        try check(try engine.inventory(app) == before,"failed preparation leaves installed app byte-identical")
        try engine.apply(app,allowLibraryValidationException:true)
        try check(engine.inspect(app).state == .applied,"apply replaces the app at its existing path")
        try check(engine.hasLibraryException(app),"ad-hoc hardened app carries the required library validation exception")
        try engine.run("/usr/bin/codesign",["--verify","--deep","--strict",app.path])
        try check(fm.fileExists(atPath:app.path),"patched app passes deep signature verification")
        // Reproduce the older GUI's signed-but-unlaunchable configuration.
        let legacyEnt = root.appendingPathComponent("legacy-entitlements.plist")
        guard let currentEnt = try MachO.entitlements(engine.binary(app)),
              var legacy = try PropertyListSerialization.propertyList(from:currentEnt,format:nil) as? [String:Any] else { throw PatchFailure.message("테스트 권한 정보 없음") }
        legacy.removeValue(forKey:"com.apple.security.cs.disable-library-validation")
        try PropertyListSerialization.data(fromPropertyList:legacy,format:.xml,options:0).write(to:legacyEnt)
        try engine.run("/usr/bin/codesign",["--force","--sign","-","--options","runtime","--entitlements",legacyEnt.path,"--generate-entitlement-der",app.path])
        var legacyRecord = try engine.loadRecord(app); legacyRecord.installedHash = try PatchSpec.hashFile(engine.binary(app)); try engine.saveRecord(legacyRecord,app)
        try check(engine.inspect(app).state == .needsRepair,"legacy library-validation failure detected before launch")
        try engine.repair(app,allowLibraryValidationException:true)
        try check(engine.inspect(app).state == .applied && engine.hasLibraryException(app),"repair rebuilds from original backup with corrected entitlements")
        let backup = engine.backupDirectory(app).appendingPathComponent("Original.backup/Contents/Info.plist")
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
        try check(try PatchSpec.hashFile(engine.binary(installed)) == installedHash,"real installed app remains unchanged during tests")
        print("ALL ENGINE INTEGRATION TESTS PASSED")
    }
}
