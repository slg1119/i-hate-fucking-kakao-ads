# 임시 서명 후 CocoaAsyncSocket 로딩 실패

개발 중인 GUI 적용 후 macOS 27.2에서 카카오톡 26.9.0이 시작 직후 종료되는 문제가 보고되었다. 사용자 보고서에는 개인 식별값이 포함되어 있어 공개 저장소에 보관하지 않는다.

## 원인

종료 단계는 `DYLD`이며 CocoaAsyncSocket을 프로세스에 매핑할 수 없다는 라이브러리 서명 검사 오류였다. 광고 함수가 실행되기 전 발생했다.

REA MCP `inspect_signature`에서 앱의 Team ID가 없고 Hardened Runtime이 켜져 있으나 라이브러리 검증 예외가 없는 것을 확인했다. CocoaAsyncSocket도 임시 서명이며 Team ID가 없었다. `trace_dylib_resolution`은 번들 안의 해당 라이브러리 경로를 찾았다. 정적 경로 후보는 실제 dyld 승인까지 증명하지 않지만, 오류 보고서의 서명 거부 사유와 함께 원인을 설명한다.

두 파일에 Team ID가 모두 없다고 같은 개발팀의 코드가 되는 것은 아니다. `codesign --verify --deep --strict` 통과도 프로세스의 라이브러리 로딩 정책 충족을 뜻하지 않는다. 초기 GUI가 이 차이를 놓쳤다.

Evidence ID:

- 앱 서명: `ev_e5a75564cff5c57a2a90f26786b662c9add780912d94b87aa1e76182f5c70d5b`
- 의존 경로: `ev_9767cedba538c961706b80146b3c20f2fbd2b72bfc955838ebdfcc9bae610dea`
- 라이브러리 서명: `ev_d55032a1d5491981ff43f727f3b900762459496eeef003b73c0aea3093f31393`

## 수정

원본 권한과 App Sandbox를 유지하고 카카오톡 및 보조 앱에 `com.apple.security.cs.disable-library-validation` 예외를 추가한다. 다른 개발자가 서명한 라이브러리의 로딩을 허용하므로 해당 앱의 보호가 완화된다. GUI에서 명시적 동의를 받으며 macOS 전체 설정이나 SIP는 변경하지 않는다.

이전 적용 기록에 예외가 없으면 `실행 복구 필요` 상태를 표시한다. 검증된 원본 백업에서 재준비한 앱으로 복구하거나 원본으로 복원할 수 있다.

독립 C 실행 파일/라이브러리의 실제 dyld 로딩 테스트와 카카오톡 임시 복사본의 이전 서명 상태 감지·복구·복원 테스트를 추가했다. 실제 사용자의 계정과 모든 화면 동작은 별도 검증 범위다.

참고: [Apple의 라이브러리 검증 예외](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.disable-library-validation), [Apple 코드 서명 가이드](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html).
