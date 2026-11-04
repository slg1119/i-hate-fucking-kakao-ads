# KakaoTalk 26.9.0 하단 배너 분석 기록

분석일: 2026-11-04. 목적: 사용자가 제공한 macOS 앱의 하단 광고 영역을 숨기는 수정 지점 확인. 설치 앱·설정·대화 데이터는 변경하지 않았고, 앱을 새로 실행하거나 디버거를 연결하지 않았다.

## 입력 식별

- 원본: `/Applications/KakaoTalk.app/Contents/MacOS/KakaoTalk`
- 버전: 26.9.0, 빌드 2006.
- universal SHA-256: `456e1a3ed7a87168888bdb8c6e4894764a028e62c0af68562a760d9909d2bb65`
- arm64 추출 SHA-256: `16cbbfe19557b33ceeef6f490c3eb0abf4b047425a261a3c84ae496bd180d83b`
- arm64 슬라이스 시작: universal 파일 오프셋 `0x2884000`.

## 확인한 호출 경로

1. Objective-C 메타데이터의 `_TtC9KakaoTalk20FSMainViewController.updateAdvertise` 구현은 `0x100c7c740`이다. Swift 구현 `0x100c7c60c`를 호출한다.
2. Swift 구현이 `0x100f06504`의 배너 갱신 함수를 호출한다. 이후 광고 영역과 구분선 표시를 갱신한다.
3. Main의 witness table `0x101f7e600 + 0x10`은 `0x101f7e648`을 참조한다. 이 테이블의 `+0x10` 슬롯은 `0x1000f5034`이고, 해당 thunk는 `0x100b0a4b0`으로 분기한다. Main 갱신 함수에서도 이 공통 함수를 두 번 직접 호출한다.
4. 공통 함수는 singleton의 `properties`를 가져와 `isCountryISOKorea`를 호출하고 결과를 반환한다. ObjC stub `0x10199f3e0`의 selector는 `properties`, `0x1019836e0`은 `isCountryISOKorea`이다.
5. 배너 갱신 함수 `0x100f06504`에서 결과의 bit 0이 0이면 `setHidden:YES`, 광고 높이 제약 `setConstant:0`, 기존 광고 뷰 `removeFromSuperview` 경로로 진행한다. 표시 경로의 높이 상수 `0x4059000000000000`은 double 100이다.
6. Main 갱신 함수의 두 직접 호출에서도 결과가 0이면 외부 광고 컨테이너를 숨기고 구분선 높이를 0으로 설정한다.

따라서 공통 함수 진입부를 `mov w0,#0; ret`로 바꾸면, 정적으로 확인한 호출 경로에서 광고를 표시하지 않는 기존 분기를 선택한다. `Banner_visibility_predicate`, `Banner_update` 등은 분석자가 붙인 이름이며 원본 심볼로 복구한 이름이 아니다.

`__TEXT,__text` 전체에서 이 함수로 향하는 직접 B/BL 명령을 조사했고 `0x1000f5034`, `0x100c7c67c`, `0x100c7c6d8` 세 곳을 확인했다. 이는 직접 분기 조사이며 간접 호출과 모든 기능의 영향 범위를 완전히 증명하지 않는다. Lock/Main이 공유하는 배너 witness 경로가 확인되므로 두 화면의 배너에 영향을 줄 수 있다. SDK의 모든 별도 네트워크 요청을 차단한다고 주장하지 않는다.

## 도구와 증거

초기 역공학 시점에는 앱 바이너리의 인덱스가 없어 외부 Mach-O·컴파일된 nib를 원본 바이트와 전용 분석 도구로 확인했다. 이후 GUI 소스는 별도로 인덱싱하여 검토했다.

### REA MCP

- 설치된 `rea-agents` 6.5.0을 `/opt/homebrew/opt/node/bin/node`로 실행하고 stdio JSON-RPC `initialize`, `tools/list`, `tools/call`을 사용했다.
- 설치된 Ghidra 12.2는 REA 6.5.0의 허용 버전 12.1.x와 다르다. 전역 REA/Codex 설정은 변경하지 않았다.
- universal 파일은 메타데이터 리더의 64 MiB 한도를 넘었다. 동일 arm64 슬라이스와 원본 Info.plist 및 Main nib 두 개로 구성한 **분석용 축소 번들**을 만들어 분석했다. 실행 가능한 완전한 앱 복사본이 아니다.
- 메타데이터 Evidence ID: `ev_c44891eb5cccde416b22a8458da286e833482ade73039510f4894d315b8ebd24`.
- nib Evidence ID: `ev_29778182325aee155136e1047664c6ea20cdb06eddbd5bcb44ca1dec7f9b7157`.
- REA 결과는 20,000개 메타데이터 레코드 한도에 도달했다. 일부 ivar 오프셋과 generic/resilient Swift 메타데이터가 미해결이다. 이 한도로 Main 구현이 누락되어, 해당 클래스와 relative method list는 별도 원본 바이트 리더로 확인했다. REA가 Main의 전체 호출 그래프를 복구했다고 주장하지 않는다.
- 큰 MCP 응답은 전송 한도를 넘었으나 분석 결과는 retained Evidence로 저장되어 `export_evidence_bundle`로 내보냈다.
- 증거: `evidence/mcp-subset/complete-evidence.json`, `evidence/focused-objc-methods.json`, `evidence/visibility-callers.json`.

### Ghidra

- Ghidra 12.2, JDK 25를 사용했다. 초기 전체 Mach-O 분석은 대화 중단으로 완료되지 않았다.
- 완료한 분석은 thin 파일을 `AARCH64:LE:64:AppleSilicon` Raw Binary로 주소 `0x100000000`에 불러오고, 확인된 함수 주소를 지정하여 디스어셈블·디컴파일한 것이다. 조사한 `__TEXT` 코드의 가상 주소와 파일 오프셋 대응은 Mach-O 세그먼트로 확인했다.
- 자동 분석을 생략했으므로 Ghidra의 C 출력은 원본 타입·ObjC 호출·Swift 호출 규약을 완전하게 복구한 소스가 아니다. selector와 witness 연결은 바이트/메타데이터 확인을 함께 사용했다.
- 원본 코드 증거: `evidence/ad-targets-raw-arm64.txt`, `evidence/ghidra-raw-console.log`.
- SDK 배너 클래스와 파일 문자열 `AdFitMac`, `AdFitBannerAdView`, `BannerAdvertisable.swift`도 바이너리에 존재한다.
- `FSMainViewController.nib`에는 `advertiseContainerView`, `advertiseContainerHeightConstraint`, `adSeparator`, `adSeparatorHeightConstraint` outlet이 기록되어 있다. nib 존재만으로 런타임 geometry를 확정하지 않았으며 실제 높이 변경은 위 코드로 확인했다.

## GUI 적용

GUI는 동일한 8바이트 변경을 검증된 원본 백업의 임시 작업본에 적용한 뒤 재서명하여 설치 경로를 교체한다. 기존 권한을 보존하면서 앱별 라이브러리 검증 예외를 추가하며 사용자의 동의를 요구한다. 원본 백업 전체 해시와 심볼릭 링크 정보를 검사하여 복원한다.

[서명 오류 분석](SIGNING-FAILURE.md)과 루트 README에 현재 동작과 검증 범위를 기록했다.
