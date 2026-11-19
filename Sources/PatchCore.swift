import Foundation
import CryptoKit
import AppKit
import Darwin

enum PatchFailure: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let s) = self { return s }; return nil }
}

struct PatchSite {
    let offset: Int
    let original: Data
    let replacement: Data
}

struct PatchProfile {
    let version: String
    let originalHash: String
    let unsignedPatchedHash: String
    let armHash: String
    let sites: [PatchSite]
}

enum PatchSpec {
    static let bundleID = "com.kakao.KakaoTalkMac"
    static let legacy = PatchProfile(
        version: "26.9.0 (2006)",
        originalHash: "456e1a3ed7a87168888bdb8c6e4894764a028e62c0af68562a760d9909d2bb65",
        unsignedPatchedHash: "c2b646df3798f94ddff7e99d32b22fd41e07afc0237227f4b2299454ba867c6c",
        armHash: "16cbbfe19557b33ceeef6f490c3eb0abf4b047425a261a3c84ae496bd180d83b",
        sites: [PatchSite(offset: 0xb0a4b0,
                          original: Data([0xf4,0x4f,0xbe,0xa9,0xfd,0x7b,0x01,0xa9]),
                          replacement: Data([0x00,0x00,0x80,0x52,0xc0,0x03,0x5f,0xd6]))]
    )
    static let current = PatchProfile(
        version: "26.10.0 (2010)",
        originalHash: "0c2b8d4d1240cffedde7232f04c7fc3875b3f667d16a69e3ed99b2bed9e83f4f",
        unsignedPatchedHash: "3ce9ce0e865fe96b5210a83c1825743b89583f66388a66ce4a480e7a4b443b4e",
        armHash: "d2b310d0122e4db3bb574b2844045b84ca782b0bcf94f8131503ee34892a5463",
        sites: [
            PatchSite(offset: 0x11e0958, original: Data([0xef,0x29,0xfa,0x97]), replacement: Data([0x00,0x00,0x80,0x52])),
            PatchSite(offset: 0x11e09b4, original: Data([0xd8,0x29,0xfa,0x97]), replacement: Data([0x00,0x00,0x80,0x52])),
            PatchSite(offset: 0x1479940, original: Data([0x80,0x04,0x00,0x36]), replacement: Data([0x24,0x00,0x00,0x14]))
        ]
    )
    static let profiles = [legacy, current]
    static func profile(for hash: String) -> PatchProfile? { profiles.first { $0.originalHash == hash } }
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func hashFile(_ url: URL) throws -> String { hash(try Data(contentsOf: url, options: .mappedIfSafe)) }

    static func patch(_ input: Data) throws -> Data {
        guard let profile = profile(for: hash(input)) else { throw PatchFailure.message("분석된 카카오톡 빌드와 다릅니다. 이 버전은 적용할 수 없습니다.") }
        let slices = try MachO.slices(input)
        guard let arm = slices.first(where: { $0.cpu == 0x0100000c }), hash(input.subdata(in: arm.offset..<arm.offset+arm.size)) == profile.armHash else {
            throw PatchFailure.message("지원하는 Apple Silicon 실행 파일이 아닙니다.")
        }
        var result = input
        for site in profile.sites {
            guard !site.original.isEmpty, site.original.count == site.replacement.count,
                  site.offset >= 0, site.offset <= arm.size - site.original.count else {
                throw PatchFailure.message("수정 지점 범위가 올바르지 않습니다.")
            }
            let p = arm.offset + site.offset
            guard input.subdata(in: p..<p+site.original.count) == site.original else {
                throw PatchFailure.message("수정 지점이 분석 결과와 다릅니다.")
            }
            result.replaceSubrange(p..<p+site.original.count, with: site.replacement)
        }
        guard hash(result) == profile.unsignedPatchedHash else { throw PatchFailure.message("패치 결과 검증에 실패했습니다.") }
        return result
    }
}

enum MachO {
    struct Slice { let cpu: UInt32; let offset: Int; let size: Int }
    static func integer(_ d: Data, _ p: Int, big: Bool = false) throws -> UInt32 {
        guard p >= 0, p <= d.count - 4 else { throw PatchFailure.message("실행 파일 구조가 올바르지 않습니다.") }
        let bytes = Array(d[p..<p+4])
        return big ? bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } : bytes.reversed().reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }
    static func slices(_ d: Data) throws -> [Slice] {
        let magic = try integer(d, 0, big: true)
        if magic == 0xcafebabe {
            let count = Int(try integer(d, 4, big: true))
            guard count > 0, count <= 16 else { throw PatchFailure.message("지원하지 않는 실행 파일 구조입니다.") }
            return try (0..<count).map { n in
                let p = 8+n*20
                let cpu = try integer(d,p,big:true), offset = Int(try integer(d,p+8,big:true)), size = Int(try integer(d,p+12,big:true))
                guard offset >= 0, size >= 32, offset <= d.count-size else { throw PatchFailure.message("실행 파일 범위가 올바르지 않습니다.") }
                return Slice(cpu: cpu, offset: offset, size: size)
            }
        }
        guard try integer(d,0) == 0xfeedfacf else { throw PatchFailure.message("Mach-O 파일이 아닙니다.") }
        return [Slice(cpu: try integer(d,4), offset: 0, size: d.count)]
    }
    // Read the original XML entitlement slot directly; codesign's display path
    // can reject that slot in a restricted host even when the bytes are valid.
    static func entitlements(_ binary: URL) throws -> Data? {
        let d = try Data(contentsOf: binary)
        let all = try slices(d)
        let s = all.first(where: { $0.cpu == 0x0100000c }) ?? all[0]
        var p = s.offset+32
        let count = Int(try integer(d,s.offset+16))
        guard count < 10000 else { throw PatchFailure.message("로드 명령 수가 올바르지 않습니다.") }
        for _ in 0..<count {
            let cmd = try integer(d,p), size = Int(try integer(d,p+4))
            guard size >= 8, p+size <= s.offset+s.size else { throw PatchFailure.message("로드 명령 범위가 올바르지 않습니다.") }
            if cmd == 0x1d {
                let start = s.offset+Int(try integer(d,p+8)), length = Int(try integer(d,p+12))
                guard length >= 12, start >= s.offset, start <= s.offset+s.size-length,
                      try integer(d,start,big:true) == 0xfade0cc0 else { throw PatchFailure.message("서명 데이터가 올바르지 않습니다.") }
                let entries = Int(try integer(d,start+8,big:true))
                guard entries <= 100, 12+entries*8 <= length else { throw PatchFailure.message("서명 슬롯 범위가 올바르지 않습니다.") }
                for i in 0..<entries where try integer(d,start+12+i*8,big:true) == 5 {
                    let b = start+Int(try integer(d,start+16+i*8,big:true))
                    let n = Int(try integer(d,b+4,big:true))
                    guard n >= 8, b >= start, b <= start+length-n, try integer(d,b,big:true) == 0xfade7171 else { throw PatchFailure.message("권한 정보가 올바르지 않습니다.") }
                    let payload = d.subdata(in: b+8..<b+n)
                    guard (try PropertyListSerialization.propertyList(from: payload, format: nil)) is [String:Any] else { throw PatchFailure.message("앱 권한 정보를 읽을 수 없습니다.") }
                    return payload
                }
                return nil
            }
            p += size
        }
        return nil
    }
}

struct BackupRecord: Codable {
    let schema: Int
    let targetPath: String
    let originalHash: String
    let createdAt: Date
    let inventory: [String:String]
    var installedHash: String?
}

enum AppState: String, Codable { case ready, applied, needsRepair, unsupported, missing, damagedBackup }
struct Inspection: Codable {
    let path: String
    let version: String
    let state: AppState
    let detail: String
    var canApply: Bool { state == .ready }
    var canRestore: Bool { state == .applied || state == .needsRepair }
    var canRepair: Bool { state == .needsRepair }
}

final class PatchEngine {
    let fm = FileManager.default
    let backupRoot: URL
    let progress: (String) -> Void
    let allowAdministrator: Bool
    init(backupRoot: URL? = nil, allowAdministrator: Bool = true, progress: @escaping (String)->Void = { _ in }) {
        self.backupRoot = backupRoot ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("NoAdKakao/Backups", isDirectory: true)
        self.progress = progress
        self.allowAdministrator = allowAdministrator
    }
    func binary(_ app: URL) -> URL { app.appendingPathComponent("Contents/MacOS/KakaoTalk") }
    func backupDirectory(_ app: URL, profile: PatchProfile = PatchSpec.legacy) -> URL {
        let pathKey = String(PatchSpec.hash(Data(app.standardizedFileURL.path.utf8)).prefix(24))
        let suffix = profile.originalHash == PatchSpec.legacy.originalHash ? "" : "-" + String(profile.originalHash.prefix(16))
        return backupRoot.appendingPathComponent(pathKey + suffix)
    }
    func recordURL(_ app: URL, profile: PatchProfile = PatchSpec.legacy) -> URL { backupDirectory(app, profile: profile).appendingPathComponent("record.json") }
    func loadRecord(_ app: URL, profile: PatchProfile = PatchSpec.legacy) throws -> BackupRecord { try JSONDecoder().decode(BackupRecord.self, from: Data(contentsOf: recordURL(app, profile: profile))) }
    func saveRecord(_ r: BackupRecord, _ app: URL, profile: PatchProfile = PatchSpec.legacy) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted,.sortedKeys]
        try encoder.encode(r).write(to: recordURL(app, profile: profile), options: .atomic)
    }
    private func withLock(_ app: URL, _ operation: () throws -> Void) throws {
        try fm.createDirectory(at:backupRoot,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        let path = backupDirectory(app).path+".lock"
        let fd = Darwin.open(path,O_CREAT|O_RDWR,0o600)
        guard fd >= 0 else { throw PatchFailure.message("작업 잠금 파일을 만들 수 없습니다.") }
        defer { Darwin.close(fd) }
        guard flock(fd,LOCK_EX|LOCK_NB) == 0 else { throw PatchFailure.message("다른 적용 또는 복원 작업이 진행 중입니다.") }
        defer { flock(fd,LOCK_UN) }
        try operation()
    }
    func hasLibraryException(_ app: URL) -> Bool {
        guard let data = try? MachO.entitlements(binary(app)),
              let d = try? PropertyListSerialization.propertyList(from:data,format:nil) as? [String:Any] else { return false }
        return d["com.apple.security.cs.disable-library-validation"] as? Bool == true
    }
    func validateApp(_ app: URL) throws -> String {
        guard app.pathExtension.lowercased() == "app", app.standardizedFileURL == app.resolvingSymlinksInPath() else { throw PatchFailure.message("실제 카카오톡 앱을 선택해주세요. 심볼릭 링크는 지원하지 않습니다.") }
        let info = app.appendingPathComponent("Contents/Info.plist")
        let dict = try PropertyListSerialization.propertyList(from: Data(contentsOf: info), format: nil) as? [String:Any]
        guard dict?["CFBundleIdentifier"] as? String == PatchSpec.bundleID,
              dict?["CFBundleExecutable"] as? String == "KakaoTalk",
              binary(app).resolvingSymlinksInPath() == binary(app) else { throw PatchFailure.message("카카오톡 앱으로 확인되지 않았습니다.") }
        return "\(dict?["CFBundleShortVersionString"] as? String ?? "?") (\(dict?["CFBundleVersion"] as? String ?? "?"))"
    }
    func inspect(_ app: URL) -> Inspection {
        do {
            let version = try validateApp(app)
            let hash = try PatchSpec.hashFile(binary(app))
            if PatchSpec.profile(for: hash) != nil { return Inspection(path: app.path,version: version,state: .ready,detail: "이 버전은 광고 영역을 숨길 수 있습니다.") }
            for profile in PatchSpec.profiles {
                if let r = try? loadRecord(app, profile: profile), r.schema == 1, r.targetPath == app.path, r.originalHash == profile.originalHash, r.installedHash == hash {
                    let saved = backupDirectory(app, profile: profile).appendingPathComponent("Original.backup/Contents/MacOS/KakaoTalk")
                    let valid = (try? PatchSpec.hashFile(saved)) == profile.originalHash
                    let repaired = hasLibraryException(app)
                    return Inspection(path: app.path,version: version,state: valid ? (repaired ? .applied : .needsRepair) : .damagedBackup,detail: valid ? (repaired ? "광고 영역 숨김이 적용되어 있습니다." : "앱 실행을 위한 서명 복구가 필요합니다.") : "원본 백업이 없거나 손상되었습니다.")
                }
            }
            return Inspection(path: app.path,version: version,state: .unsupported,detail: "분석된 Apple Silicon 빌드만 지원합니다.")
        } catch { return Inspection(path: app.path,version: "—",state: .missing,detail: error.localizedDescription) }
    }
    func ensureStopped(_ app: URL) throws {
        let running = NSRunningApplication.runningApplications(withBundleIdentifier: PatchSpec.bundleID)
        guard !running.contains(where: { $0.bundleURL?.standardizedFileURL == app.standardizedFileURL }) else { throw PatchFailure.message("먼저 카카오톡을 완전히 종료해주세요.") }
    }
    @discardableResult func run(_ executable: String, _ arguments: [String]) throws -> String {
        let task = Process(); task.executableURL = URL(fileURLWithPath: executable); task.arguments = arguments
        let pipe = Pipe(); task.standardOutput = pipe; task.standardError = pipe
        try task.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile(); task.waitUntilExit()
        let output = String(decoding: data,as: UTF8.self)
        guard task.terminationStatus == 0 else { throw PatchFailure.message("\(URL(fileURLWithPath: executable).lastPathComponent) 실패 (\(task.terminationStatus))\n\(output.suffix(5000))") }
        return output
    }
    func copy(_ a: URL, _ b: URL) throws { try run("/usr/bin/ditto",[a.path,b.path]) }
    func inventory(_ root: URL) throws -> [String:String] {
        let root = root.resolvingSymlinksInPath().standardizedFileURL
        var result: [String:String] = [:]
        func visit(_ directory: URL, prefix: String) throws {
            for name in try fm.contentsOfDirectory(atPath:directory.path).sorted() {
                let key = prefix.isEmpty ? name : prefix+"/"+name
                let url = directory.appendingPathComponent(name)
                let attrs = try fm.attributesOfItem(atPath:url.path)
                switch attrs[.type] as? FileAttributeType {
                case .typeSymbolicLink: result[key] = "link:" + (try fm.destinationOfSymbolicLink(atPath:url.path))
                case .typeRegular: result[key] = try PatchSpec.hashFile(url)
                case .typeDirectory: result[key] = "directory"; try visit(url,prefix:key)
                default: throw PatchFailure.message("지원하지 않는 백업 파일 형식입니다: "+key)
                }
            }
        }
        try visit(root,prefix:"")
        return result
    }
    func executableInBundle(_ root: URL) -> URL? {
        for location in ["Contents/Info.plist","Resources/Info.plist","Versions/Current/Resources/Info.plist"] {
            if let d = try? Data(contentsOf: root.appendingPathComponent(location)),
               let p = try? PropertyListSerialization.propertyList(from:d,format:nil) as? [String:Any],
               let name = p["CFBundleExecutable"] as? String {
                let candidates = [root.appendingPathComponent("Contents/MacOS/"+name),root.appendingPathComponent(name),root.appendingPathComponent("Versions/Current/"+name)]
                if let file = candidates.first(where: { fm.fileExists(atPath: $0.path) }) { return file }
            }
        }
        return nil
    }
    func sign(_ staged: URL, _ working: URL, profile: PatchProfile) throws {
        guard let beforeEntitlements = try MachO.entitlements(binary(staged)) else { throw PatchFailure.message("원본 앱의 권한 정보를 찾지 못했습니다.") }
        guard var beforeDictionary = try PropertyListSerialization.propertyList(from:beforeEntitlements,format:nil) as? [String:Any] else { throw PatchFailure.message("앱 권한 정보를 읽지 못했습니다.") }
        beforeDictionary["com.apple.security.cs.disable-library-validation"] = true
        var units: [URL] = []
        if let enumerator = fm.enumerator(at: staged,includingPropertiesForKeys: [.isSymbolicLinkKey]) {
            for case let u as URL in enumerator {
                guard (try? u.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) != true else { continue }
                if ["framework","appex","xpc","app"].contains(u.pathExtension), executableInBundle(u) != nil { units.append(u) }
                else if u.pathExtension == "dylib" { units.append(u) }
            }
        }
        units.sort { $0.pathComponents.count > $1.pathComponents.count }; units.append(staged)
        for (index, unit) in units.enumerated() {
            let exec = unit.pathExtension == "dylib" ? unit : executableInBundle(unit)
            guard let exec else { throw PatchFailure.message("서명할 실행 파일을 찾지 못했습니다.") }
            var entitlements = try MachO.entitlements(exec)
            if ["app","appex","xpc"].contains(unit.pathExtension) {
                var dict: [String:Any] = [:]
                if let data = entitlements { dict = (try PropertyListSerialization.propertyList(from:data,format:nil) as? [String:Any]) ?? [:] }
                dict["com.apple.security.cs.disable-library-validation"] = true
                entitlements = try PropertyListSerialization.data(fromPropertyList:dict,format:.xml,options:0)
            }
            var args = ["--force","--sign","-","--timestamp=none"]
            if ["app","appex","xpc"].contains(unit.pathExtension) { args += ["--options","runtime"] }
            if let entitlements {
                let ent = working.appendingPathComponent("entitlements-\(index).plist")
                try entitlements.write(to: ent); args += ["--entitlements",ent.path,"--generate-entitlement-der"]
            }
            try run("/usr/bin/codesign",args+[unit.path])
        }
        try run("/usr/bin/codesign",["--verify","--deep","--strict",staged.path])
        // Keep the original main entitlement dictionary, including App Sandbox.
        let original = try MachO.entitlements(binary(staged))
        guard let original,
              let d = try PropertyListSerialization.propertyList(from:original,format:nil) as? NSDictionary,
              d == beforeDictionary as NSDictionary,
              d["com.apple.security.app-sandbox"] as? Bool == true else { throw PatchFailure.message("재서명 후 앱 권한 보존을 확인하지 못했습니다.") }
        let signed = try Data(contentsOf:binary(staged))
        guard let arm = try MachO.slices(signed).first(where: { $0.cpu == 0x0100000c }) else { throw PatchFailure.message("재서명 후 Apple Silicon 실행 파일을 찾지 못했습니다.") }
        for site in profile.sites {
            guard site.offset >= 0, site.offset <= arm.size - site.replacement.count,
                  signed.subdata(in:arm.offset+site.offset..<arm.offset+site.offset+site.replacement.count) == site.replacement else {
                throw PatchFailure.message("재서명 후 패치 검증에 실패했습니다.")
            }
        }
    }
    func quote(_ s: String) -> String { "'" + s.replacingOccurrences(of:"'",with:"'\\''") + "'" }
    func install(_ staged: URL, at target: URL, expectedCurrent: String, expectedNew: String, verifySignature: Bool) throws {
        let parent = target.deletingLastPathComponent()
        let id = UUID().uuidString
        let incoming = parent.appendingPathComponent(".NoAdKakao-incoming-\(id).app")
        let previous = parent.appendingPathComponent(".NoAdKakao-previous-\(id).backup")
        let q = quote
        let script = """
        set -eu
        target=\(q(target.path))
        incoming=\(q(incoming.path))
        previous=\(q(previous.path))
        current=$(/usr/bin/shasum -a 256 "$target/Contents/MacOS/KakaoTalk" | /usr/bin/awk '{print $1}')
        [ "$current" = \(q(expectedCurrent)) ] || { echo '작업 중 카카오톡이 변경되었습니다.'; exit 1; }
        [ ! -e "$incoming" ] && [ ! -e "$previous" ]
        /usr/bin/ditto \(q(staged.path)) "$incoming"
        candidate=$(/usr/bin/shasum -a 256 "$incoming/Contents/MacOS/KakaoTalk" | /usr/bin/awk '{print $1}')
        [ "$candidate" = \(q(expectedNew)) ] || { echo '설치 후보 검증 실패'; exit 1; }
        \(verifySignature ? "/usr/bin/codesign --verify --deep --strict \"$incoming\"" : ":")
        current=$(/usr/bin/shasum -a 256 "$target/Contents/MacOS/KakaoTalk" | /usr/bin/awk '{print $1}')
        [ "$current" = \(q(expectedCurrent)) ] || { echo '작업 중 카카오톡이 변경되었습니다.'; exit 1; }
        rollback() {
          if [ -e "$previous" ]; then
            if [ -e "$target" ]; then /bin/mv "$target" "$incoming.failed"; fi
            /bin/mv "$previous" "$target"
          fi
        }
        trap rollback EXIT HUP INT TERM
        /bin/mv "$target" "$previous"
        /bin/mv "$incoming" "$target"
        installed=$(/usr/bin/shasum -a 256 "$target/Contents/MacOS/KakaoTalk" | /usr/bin/awk '{print $1}')
        [ "$installed" = \(q(expectedNew)) ] || { echo '설치 결과 검증 실패'; exit 1; }
        trap - EXIT HUP INT TERM
        /bin/rm -rf "$previous" || true
        """
        if fm.isWritableFile(atPath: parent.path) && fm.isWritableFile(atPath: target.path) {
            try run("/bin/sh",["-c",script])
        } else {
            guard allowAdministrator else { throw PatchFailure.message("이 위치에는 관리자 권한이 필요합니다.") }
            let escaped = script.replacingOccurrences(of:"\\",with:"\\\\").replacingOccurrences(of:"\"",with:"\\\"").replacingOccurrences(of:"\n",with:"\\n")
            try run("/usr/bin/osascript",["-e","do shell script \"\(escaped)\" with administrator privileges"])
        }
    }
    func apply(_ app: URL, allowLibraryValidationException: Bool = false, simulateFailure: Bool = false) throws {
        guard allowLibraryValidationException else { throw PatchFailure.message("앱별 라이브러리 서명 검증 예외를 허용한 후 적용할 수 있습니다.") }
        try withLock(app) { try applyUnlocked(app,simulateFailure:simulateFailure) }
    }
    private func applyUnlocked(_ app: URL, simulateFailure: Bool) throws {
        let app = app.standardizedFileURL
        guard inspect(app).canApply else { throw PatchFailure.message("이 앱에는 패치를 적용할 수 없습니다. 상태를 다시 확인해주세요.") }
        try ensureStopped(app)
        let original = try Data(contentsOf: binary(app)); let candidate = try PatchSpec.patch(original)
        guard let profile = PatchSpec.profile(for: PatchSpec.hash(original)) else { throw PatchFailure.message("지원하지 않는 원본입니다.") }
        let dir = backupDirectory(app, profile: profile)
        guard !fm.fileExists(atPath: dir.path) else {
            // Reuse a verified original after a previous completed restore.
            let record = try loadRecord(app, profile: profile)
            let saved = dir.appendingPathComponent("Original.backup")
            guard record.targetPath == app.path, record.originalHash == profile.originalHash, try inventory(saved) == record.inventory else { throw PatchFailure.message("기존 백업을 확인할 수 없습니다. 백업 폴더를 확인해주세요.") }
            try applyWithBackup(app,candidate: candidate,record: record,profile: profile,simulateFailure: simulateFailure)
            return
        }
        try fm.createDirectory(at: dir,withIntermediateDirectories: true,attributes: [.posixPermissions:0o700])
        progress("원본 앱을 백업하고 있습니다…")
        let saved = dir.appendingPathComponent("Original.backup")
        do {
            try copy(app,saved)
            let index = try inventory(saved)
            let sourceIndex = try inventory(app)
            guard sourceIndex == index, try PatchSpec.hashFile(binary(saved)) == profile.originalHash else {
                let differences = Set(sourceIndex.keys).union(index.keys).filter { sourceIndex[$0] != index[$0] }.sorted().prefix(6)
                throw PatchFailure.message("원본 백업 검증에 실패했습니다.\n" + differences.joined(separator:"\n"))
            }
            let record = BackupRecord(schema:1,targetPath:app.path,originalHash:profile.originalHash,createdAt:Date(),inventory:index,installedHash:nil)
            try saveRecord(record,app,profile:profile)
            try applyWithBackup(app,candidate:candidate,record:record,profile:profile,simulateFailure:simulateFailure)
        } catch {
            if !fm.fileExists(atPath: recordURL(app, profile: profile).path) { try? fm.removeItem(at:dir) }
            throw error
        }
    }
    private func applyWithBackup(_ app: URL, candidate: Data, record: BackupRecord, profile: PatchProfile, simulateFailure: Bool, expectedCurrent: String? = nil) throws {
        let expectedCurrent = expectedCurrent ?? profile.originalHash
        let dir = backupDirectory(app, profile: profile), work = dir.appendingPathComponent("work-"+UUID().uuidString)
        try fm.createDirectory(at:work,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        defer { try? fm.removeItem(at:work) }
        let staged = work.appendingPathComponent("KakaoTalk.app")
        progress("광고 영역 숨김을 준비하고 있습니다…")
        try copy(dir.appendingPathComponent("Original.backup"),staged)
        try candidate.write(to:binary(staged),options:.atomic)
        try fm.setAttributes([.posixPermissions:0o755],ofItemAtPath:binary(staged).path)
        progress("앱 권한과 서명을 확인하고 있습니다…")
        try sign(staged,work,profile:profile)
        let signedHash = try PatchSpec.hashFile(binary(staged))
        if simulateFailure { throw PatchFailure.message("테스트: 설치 직전 중단") }
        try ensureStopped(app)
        if expectedCurrent == profile.originalHash {
            guard try inventory(app) == record.inventory else { throw PatchFailure.message("준비 중 앱 내용이 변경되어 적용을 중단했습니다.") }
        } else {
            guard try PatchSpec.hashFile(binary(app)) == expectedCurrent else { throw PatchFailure.message("준비 중 앱 내용이 변경되어 복구를 중단했습니다.") }
        }
        var updated = record; updated.installedHash = signedHash
        try saveRecord(updated,app,profile:profile) // Persist recovery information before the swap.
        progress("설치된 카카오톡에 적용하고 있습니다…")
        try install(staged,at:app,expectedCurrent:expectedCurrent,expectedNew:signedHash,verifySignature:true)
        guard inspect(app).state == .applied else { throw PatchFailure.message("설치 후 상태 확인에 실패했습니다. 원본 복원을 사용해주세요.") }
    }
    private func matchingRecord(_ app: URL) throws -> (PatchProfile, BackupRecord) {
        let current = try PatchSpec.hashFile(binary(app))
        let matches = PatchSpec.profiles.compactMap { profile -> (PatchProfile, BackupRecord)? in
            guard let record = try? loadRecord(app, profile: profile), record.schema == 1,
                  record.targetPath == app.path, record.originalHash == profile.originalHash,
                  record.installedHash == current else { return nil }
            return (profile, record)
        }
        guard matches.count == 1, let match = matches.first else { throw PatchFailure.message("현재 앱에 해당하는 백업 기록을 확인하지 못했습니다.") }
        return match
    }

    func repair(_ app: URL, allowLibraryValidationException: Bool = false) throws {
        guard allowLibraryValidationException else { throw PatchFailure.message("앱별 라이브러리 서명 검증 예외에 대한 동의가 필요합니다.") }
        try withLock(app) {
            guard inspect(app).canRepair else { throw PatchFailure.message("복구할 이전 적용 기록이 없습니다.") }
            try ensureStopped(app)
            let (profile, record) = try matchingRecord(app)
            let saved = backupDirectory(app, profile: profile).appendingPathComponent("Original.backup")
            guard let current = record.installedHash, try inventory(saved) == record.inventory else { throw PatchFailure.message("원본 백업이 변경되어 복구를 중단했습니다.") }
            let candidate = try PatchSpec.patch(Data(contentsOf:binary(saved)))
            try applyWithBackup(app,candidate:candidate,record:record,profile:profile,simulateFailure:false,expectedCurrent:current)
        }
    }
    func restore(_ app: URL) throws { try withLock(app) { try restoreUnlocked(app) } }
    private func restoreUnlocked(_ app: URL) throws {
        let app = app.standardizedFileURL
        guard inspect(app).canRestore else { throw PatchFailure.message("복원 가능한 적용 기록이 없습니다.") }
        try ensureStopped(app)
        let (profile, record) = try matchingRecord(app)
        let saved = backupDirectory(app, profile: profile).appendingPathComponent("Original.backup")
        progress("원본 백업 전체를 확인하고 있습니다…")
        guard try inventory(saved) == record.inventory, try PatchSpec.hashFile(binary(saved)) == profile.originalHash,
              let current = record.installedHash else { throw PatchFailure.message("백업이 변경되어 복원을 중단했습니다. 현재 앱은 유지됩니다.") }
        progress("원래 카카오톡으로 복원하고 있습니다…")
        try install(saved,at:app,expectedCurrent:current,expectedNew:profile.originalHash,verifySignature:false)
        guard try inventory(app) == record.inventory else { throw PatchFailure.message("복원 파일 검증에 실패했습니다. 원본 백업은 보관되어 있습니다.") }
    }
}
