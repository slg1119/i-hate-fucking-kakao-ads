import SwiftUI
import AppKit
import UniformTypeIdentifiers

@MainActor final class AppDelegate: NSObject, NSApplicationDelegate {
    static var operationInProgress = false
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard Self.operationInProgress else { return .terminateNow }
        let alert = NSAlert()
        alert.messageText = "현재 작업을 마친 뒤 종료할 수 있습니다."
        alert.informativeText = "앱 교체나 원본 복원이 끝날 때까지 잠시 기다려주세요."
        alert.addButton(withTitle:"확인")
        alert.runModal()
        return .terminateCancel
    }
}

@MainActor final class AppModel: ObservableObject {
    @Published var target = URL(fileURLWithPath:"/Applications/KakaoTalk.app")
    @Published var inspection: Inspection?
    @Published var busy = false
    @Published var activity = "카카오톡을 확인하고 있습니다…"
    @Published var detailLog = ""
    @Published var notice: String?
    @Published var failed = false
    var canApply: Bool { !busy && inspection?.canApply == true }
    var canRestore: Bool { !busy && inspection?.canRestore == true }
    var canRepair: Bool { !busy && inspection?.canRepair == true }
    func refresh() {
        guard !busy else { return }
        busy = true
        let path = target
        Task {
            let result = await Task.detached { PatchEngine().inspect(path) }.value
            self.inspection = result; self.busy = false; self.activity = ""
        }
    }
    func choose() {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.applicationBundle]
        panel.canChooseDirectories = false; panel.canChooseFiles = true; panel.allowsMultipleSelection = false
        panel.directoryURL = URL(fileURLWithPath:"/Applications")
        panel.message = "광고 영역을 숨길 카카오톡 앱을 선택하세요."
        if panel.runModal() == .OK, let url = panel.url { select(url) }
    }
    func select(_ url: URL) { guard !busy else { return }; target = url.standardizedFileURL; notice = nil; detailLog = ""; refresh() }
    func perform(restore: Bool, repair: Bool = false) {
        guard restore ? canRestore : (repair ? canRepair : canApply) else { return }
        if !restore {
            let consent = NSAlert(); consent.messageText = "카카오톡에 서명 예외를 적용할까요?"
            consent.informativeText = "수정된 앱의 실행을 위해 이 카카오톡과 포함된 보조 앱의 라이브러리 서명 검증을 완화합니다. 다른 개발자가 서명한 라이브러리도 불러올 수 있게 됩니다.\n\nmacOS 전체 보안 설정은 유지되며, 원본 복원 시 이 예외도 제거됩니다. 실행 중인 카카오톡은 강제 종료합니다. 작성 중인 내용이 저장되지 않을 수 있습니다."
            consent.addButton(withTitle: "예외를 허용하고 \(repair ? "복구" : "적용")")
            consent.addButton(withTitle:"취소")
            guard consent.runModal() == .alertFirstButtonReturn else { return }
        }
        let running = NSRunningApplication.runningApplications(withBundleIdentifier:PatchSpec.bundleID).filter { $0.bundleURL?.standardizedFileURL == target.standardizedFileURL }
        busy = true; failed = false; notice = nil; detailLog = ""; activity = "준비하고 있습니다…"
        AppDelegate.operationInProgress = true
        let path = target
        Task {
            defer { AppDelegate.operationInProgress = false }
            do {
                if !running.isEmpty {
                    self.activity = "실행 중인 카카오톡을 강제 종료하고 있습니다…"
                    self.detailLog += self.activity+"\n"
                    running.forEach { _ = $0.forceTerminate() }
                    for _ in 0..<40 {
                        if running.allSatisfy({ $0.isTerminated }) { break }
                        try? await Task.sleep(nanoseconds:125_000_000)
                    }
                    guard running.allSatisfy({ $0.isTerminated }) else { throw PatchFailure.message("카카오톡 강제 종료를 확인하지 못해 파일 교체를 중단했습니다.") }
                }
                try await Task.detached { [weak model = self] in
                    let engine = PatchEngine { text in
                        Task { @MainActor [weak model] in model?.activity = text; model?.detailLog += text+"\n" }
                    }
                    if restore { try engine.restore(path) }
                    else if repair { try engine.repair(path,allowLibraryValidationException:true) }
                    else { try engine.apply(path,allowLibraryValidationException:true) }
                }.value
                self.notice = restore ? "원래 카카오톡으로 복원했습니다." : "\(repair ? "서명을 복구" : "적용")했습니다. 카카오톡을 열어 확인하세요."
                self.failed = false
            } catch {
                self.failed = true
                self.notice = "작업을 완료하지 못했습니다. 아래 내용을 확인해주세요."
                self.detailLog += error.localizedDescription+"\n"
            }
            self.inspection = await Task.detached { PatchEngine().inspect(path) }.value
            self.busy = false; self.activity = ""
        }
    }
    func openKakao() { NSWorkspace.shared.open(target) }
    func showBackups() {
        let url = PatchEngine().backupRoot
        if FileManager.default.fileExists(atPath:url.path) { NSWorkspace.shared.open(url) }
    }
}

struct YellowActionStyle: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.system(size:13,weight:.semibold)).padding(.horizontal,18).frame(height:36)
            .foregroundStyle(enabled ? Color.black.opacity(0.86) : Color.secondary)
            .background(enabled ? Color(red:0.98,green:0.84,blue:0.19).opacity(configuration.isPressed ? 0.78 : 1) : Color.primary.opacity(0.06),in:RoundedRectangle(cornerRadius:10))
    }
}

struct ContentView: View {
    @StateObject private var model = AppModel()
    @State private var isDropping = false
    @State private var showDetails = false
    private let yellow = Color(red:0.98,green:0.84,blue:0.19)
    var stateTitle: String {
        switch model.inspection?.state {
        case .ready: return "적용 가능"
        case .applied: return "적용됨"
        case .needsRepair: return "실행 복구 필요"
        case .unsupported: return "지원하지 않는 버전"
        case .damagedBackup: return "백업 확인 필요"
        case .missing: return "앱 선택 필요"
        case nil: return "확인 중"
        }
    }
    var statusColor: Color {
        switch model.inspection?.state { case .ready,.applied: return .green; case .needsRepair,.unsupported,.damagedBackup: return .orange; default:return .secondary }
    }
    var body: some View {
        VStack(alignment:.leading,spacing:0) {
            HStack(alignment:.top,spacing:18) {
                ZStack {
                    RoundedRectangle(cornerRadius:19,style:.continuous).fill(yellow)
                    Image(systemName:"bubble.left.fill").font(.system(size:32,weight:.semibold)).foregroundStyle(Color.black.opacity(0.83))
                    Image(systemName:"minus").font(.system(size:18,weight:.bold)).foregroundStyle(yellow).offset(y:-2)
                }.frame(width:76,height:76).accessibilityHidden(true)
                VStack(alignment:.leading,spacing:9) {
                    Text("대화에만 집중하세요.").font(.system(size:28,weight:.bold)).tracking(-0.8)
                    Text("설치된 카카오톡의 하단 광고 영역을 숨깁니다.").font(.system(size:14)).foregroundStyle(.secondary)
                }.padding(.top,7)
                Spacer(minLength:0)
            }.padding(.bottom,30)

            VStack(alignment:.leading,spacing:18) {
                HStack(spacing:14) {
                    Image(nsImage:NSWorkspace.shared.icon(forFile:model.target.path)).resizable().interpolation(.high).frame(width:52,height:52)
                    VStack(alignment:.leading,spacing:5) {
                        HStack(spacing:9) {
                            Text("카카오톡").font(.system(size:16,weight:.semibold))
                            Text(stateTitle).font(.system(size:11,weight:.medium)).padding(.horizontal,9).padding(.vertical,4)
                                .background(statusColor.opacity(0.12),in:Capsule()).foregroundStyle(statusColor)
                        }
                        Text(model.inspection?.version ?? "버전 확인 중").font(.system(size:12)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("앱 선택…") { model.choose() }.disabled(model.busy).controlSize(.regular)
                }
                Text(model.target.path).font(.system(size:11,design:.monospaced)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                Divider()
                Label(model.inspection?.detail ?? "설치된 앱을 확인하고 있습니다.",systemImage:model.inspection?.state == .applied ? "checkmark.circle.fill" : "info.circle")
                    .font(.system(size:12)).foregroundStyle(.secondary).fixedSize(horizontal:false,vertical:true)
            }
            .padding(22)
            .background(Color(nsColor:.controlBackgroundColor),in:RoundedRectangle(cornerRadius:16,style:.continuous))
            .overlay(RoundedRectangle(cornerRadius:16).strokeBorder(isDropping ? yellow : Color.primary.opacity(0.07),lineWidth:isDropping ? 2 : 1))
            .onDrop(of:[UTType.fileURL.identifier],isTargeted:$isDropping) { items in
                guard !model.busy, let item = items.first else { return false }
                _ = item.loadObject(ofClass:URL.self) { url,_ in if let url { Task { @MainActor in model.select(url) } } }
                return true
            }

            VStack(alignment:.leading,spacing:10) {
                Label("원본 앱을 자동으로 백업합니다.",systemImage:"arrow.uturn.backward.circle").font(.system(size:13,weight:.medium))
                Text("실행을 위한 앱별 서명 예외가 필요하며 적용 전에 동의를 받습니다.\nmacOS 권한 확인이나 재로그인이 필요할 수 있습니다.")
                    .font(.system(size:12)).foregroundStyle(.secondary).lineSpacing(4)
                Text("작업 시 실행 중인 카카오톡은 강제 종료됩니다.").font(.system(size:11)).foregroundStyle(.secondary)
            }.padding(.top,23).padding(.horizontal,2)

            if model.busy {
                HStack(spacing:11) { ProgressView().controlSize(.small); Text(model.activity).font(.system(size:12)).foregroundStyle(.secondary) }
                    .padding(.top,20).accessibilityElement(children:.combine)
            }
            if let notice = model.notice {
                Label(notice,systemImage:model.failed ? "exclamationmark.circle.fill" : "checkmark.circle.fill")
                    .font(.system(size:12,weight:.medium)).foregroundStyle(model.failed ? Color.orange : Color.green)
                    .padding(.top,18).fixedSize(horizontal:false,vertical:true)
            }
            if !model.detailLog.isEmpty {
                DisclosureGroup("작업 기록",isExpanded:$showDetails) {
                    ScrollView { Text(model.detailLog).font(.system(size:10,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading) }.frame(height:78)
                    HStack { Spacer(); Button("기록 복사") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(model.detailLog,forType:.string) }.controlSize(.small) }
                }.font(.system(size:11)).padding(.top,14)
            }
            Spacer(minLength:24)
            HStack(spacing:10) {
                Button("백업 폴더") { model.showBackups() }.buttonStyle(.link).font(.system(size:11)).disabled(model.busy)
                Spacer()
                if model.inspection?.state == .needsRepair {
                    Button("원래대로 복원") { model.perform(restore:true) }.disabled(!model.canRestore).controlSize(.large)
                    Button("실행 오류 복구") { model.perform(restore:false,repair:true) }.buttonStyle(YellowActionStyle()).disabled(!model.canRepair)
                } else if model.inspection?.state == .applied {
                    Button("원래대로 복원") { model.perform(restore:true) }.disabled(!model.canRestore).controlSize(.large)
                    Button("카카오톡 열기") { model.openKakao() }.buttonStyle(YellowActionStyle()).disabled(model.busy)
                } else {
                    Button("다시 확인") { model.refresh() }.disabled(model.busy).controlSize(.large)
                    Button("백업하고 적용") { model.perform(restore:false) }.buttonStyle(YellowActionStyle()).disabled(!model.canApply)
                }
            }
        }
        .padding(32).frame(width:680).frame(minHeight:530)
        .background(Color(nsColor:.windowBackgroundColor))
        .onAppear { model.refresh() }
    }
}

@main struct NoAdKakaoApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    init() {
        if CommandLine.arguments.contains("--self-test") {
            do { try EngineTests.run(); exit(0) } catch { fputs("SELF-TEST FAILED: \(error)\n",stderr); exit(1) }
        }
        NSApplication.shared.setActivationPolicy(.regular)
    }
    var body: some Scene {
        Window("카카오 광고 정리",id:"main") { ContentView() }
            .windowResizability(.contentSize).defaultPosition(.center)
            .commands { CommandGroup(replacing:.newItem) {} }
    }
}
