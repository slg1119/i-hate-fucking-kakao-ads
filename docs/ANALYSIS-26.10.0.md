# KakaoTalk 26.10.0 하단 광고 영역 정적 분석

분석일: 2026-11-19. 설치된 앱을 실행하거나 수정하지 않고 실행 파일 복사본을 분석했다. 아래는 Apple Silicon 코드의 정적 근거이며, 실제 로그인·화면 표시·서명 후 실행 검증은 아니다.

## 입력과 패치 식별

- 입력: `/Applications/KakaoTalk.app/Contents/MacOS/KakaoTalk`, Info.plist 버전 `26.10.0`, 빌드 `2010`, 번들 ID `com.kakao.KakaoTalkMac`.
- `codesign --verify --deep --strict` 종료 코드 0. 코드 서명 표시상 Team ID `L75WVXX68A`, Apple Mac OS Application Signing 인증 체인. 원본 전체 SHA-256은 분석 전후 동일했다. 이 검사는 현재 파일의 무결성 근거이며 별도로 배포처를 조회한 것은 아니다.
- universal SHA-256: `0c2b8d4d1240cffedde7232f04c7fc3875b3f667d16a69e3ed99b2bed9e83f4f`.
- arm64 SHA-256: `d2b310d0122e4db3bb574b2844045b84ca782b0bcf94f8131503ee34892a5463`.
- universal에는 x86_64와 arm64가 있으며 arm64 슬라이스의 시작은 `0x28b8000`, 크기는 `0x24452f0`이다. arm64 load command에서 `LC_ENCRYPTION_INFO`/`LC_ENCRYPTION_INFO_64`는 발견되지 않았다.
- 공통 판정 함수는 주소 `0x10106b114`에 있지만 수정하지 않는다. 광고 화면에서만 다음 세 명령을 수정한다. 바이트는 파일 순서다.

| 가상 주소 | arm64 상대 오프셋 | universal 오프셋 | 원본 | 변경 |
| --- | --- | --- | --- | --- |
| `0x1011e0958` | `0x11e0958` | `0x3a98958` | `ef 29 fa 97` (`bl 0x10106b114`) | `00 00 80 52` (`mov w0, #0`) |
| `0x1011e09b4` | `0x11e09b4` | `0x3a989b4` | `d8 29 fa 97` (`bl 0x10106b114`) | `00 00 80 52` (`mov w0, #0`) |
| `0x101479940` | `0x1479940` | `0x3d31940` | `80 04 00 36` (`tbz w0, #0, 0x1014799d0`) | `24 00 00 14` (`b 0x1014799d0`) |

- 세 명령의 12바이트 범위만 수정한 **서명 전** universal SHA-256: `3ce9ce0e865fe96b5210a83c1825743b89583f66388a66ce4a480e7a4b443b4e`. 실제로 다른 바이트는 11개이며, 나머지 한 바이트는 원본과 우연히 같다. 그 밖의 바이트와 공통 판정 함수는 동일하다. 코드 서명이 무효화된 분석 후보이며 재서명된 앱의 해시가 아니다.
- 앞서 공통 판정 함수의 첫 8바이트를 바꾸는 후보도 조사했으나, 다른 간접 호출에 미치는 영향을 제한하기 위해 위 세 지점 후보를 선택했다.

## 호출과 레이아웃 근거

1. ObjC 메타데이터의 `_TtC9KakaoTalk20FSMainViewController` relative method list에서 selector `updateAdvertise`는 `0x1011e0a1c`이다. 이 구현은 `0x1011e08e8`을 호출한다. Swift 메서드 이름은 분석 편의상 설명한 것이며 복구된 심볼명이 아니다.
2. `0x1011e08e8`은 배너 업데이트 `0x1014798e8`을 호출하고 `0x10106b114`를 `0x1011e0958` 및 `0x1011e09b4`에서 두 번 직접 호출한다. 첫 결과를 반전해 ObjC `setHidden:`에 전달하고, 두 번째 결과로 구분선 제약 `setConstant:`에 1 또는 0을 전달한다. 두 BL을 `mov w0, #0`으로 대체하면 컨테이너 숨김과 구분선 높이 0 경로를 택한다. 이 두 호출은 생략되므로 원래 함수가 수행할 수 있는 초기화 등 부작용도 생략된다. 정적 분석만으로 이 부작용의 전체 영향을 배제할 수 없다.
3. 배너 업데이트는 테이블 `0x101f99bd0 + 0x10` → `0x101f99c18`의 `+0x10` → `0x10061a37c`로 간접 호출한다. 해당 thunk는 `0x10106b114`로 분기한다. 배너 함수의 `0x101479940`을 무조건 분기로 바꾸면 기존 판정 함수 호출은 유지한 채 `0x1014799d0`으로 분기해 `setHidden:YES`, `setConstant:0`, 기존 뷰 `removeFromSuperview`를 수행한다. 표시 분기에는 `100.0` 높이가 있다. 이 흐름과 Main 직접 호출이 서로 독립적인 연결 근거다.
4. 판정 함수는 `0x100add970`의 반환값을 역참조해 `properties` selector를 호출하고, 이어 `isCountryISOKorea` selector의 결과를 반환한다. selector는 ObjC stub `0x1019af5c0`, `0x101993ac0`과 각각의 selector reference 원본 바이트를 통해 확인했다. `setHidden:`, `setConstant:`, `removeFromSuperview` 역시 각각 stub `0x1019c8b60`, `0x1019c22a0`, `0x1019b3420`에서 selector reference를 해석해 확인했다.

arm64 `__TEXT,__text` 전체의 직접 B/BL 대상 검사에서 함수로 향하는 세 명령은 `0x10061a37c`, `0x1011e0958`, `0x1011e09b4`였다. 이는 직접 분기만의 결과이며 모든 간접 호출이나 다른 기능에 대한 영향이 없다는 증명은 아니다. 코드 변경은 이 광고 갱신 경로의 세 명령에 국한되며 공통 판정 함수와 인증 코드는 수정하지 않는다. 해당 경로의 다른 간접 호출과 호출 생략의 부작용까지 정적으로 완전히 배제한 것은 아니다. 별도 광고 네트워크 요청의 차단은 확인하지 않았다.

## 도구와 한계

REA 6.5.0 stdio MCP의 `initialize`와 `open_binary`로 arm64 복사본과 SHA-256을 확인했다. `read_bytes`는 설치된 Ghidra 12.2가 REA의 12.1.x 요구 범위 밖이라 `provider_unavailable`로 실패했다. REA 결과를 디컴파일로 지칭하지 않는다.

Homebrew Ghidra 12.2의 macOS ARM64 네이티브 디컴파일러를 사용해 arm64 파일을 Raw Binary, `AARCH64:LE:64:AppleSilicon`, base `0x100000000`으로 가져오고 위 함수 세 곳을 지정해 디컴파일했다. 자동 분석 없이 생성한 결과이므로 Swift/ObjC 타입과 호출 규약은 복구되지 않았다. Mach-O 세그먼트에서 해당 `__TEXT` 주소와 파일 오프셋이 대응함을 확인하고, 별도 Capstone 명령어 해석과 ObjC 메타데이터·selector reference로 연결을 교차검증했다. Ghidra 출력의 thunk 함수 병합은 독립 명령어 해석으로 구분했다.

재현용 복사본과 스크립트, REA 결과, Ghidra 로그는 Git 제외 경로 `analysis/2026-11-19/`에 있다. `PYTHONPATH=analysis/2026-11-19/python python3 analysis/2026-11-19/verify_narrow.py`는 복사본에서 슬라이스·원본 명령·분기 대상·바뀐 범위·해시를 확인하고 독립 후보 파일을 만든다. 전용 `python` 경로에는 분석용 Capstone이 설치돼 있다. 설치된 앱 및 사용자 계정 데이터는 건드리지 않았다.
