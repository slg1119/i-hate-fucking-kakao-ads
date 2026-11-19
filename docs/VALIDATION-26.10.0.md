# 26.10.0 (2010) 검증 기록

검증일: 2026-11-19. 대상은 전체 SHA-256이 `0c2b8d4d1240cffedde7232f04c7fc3875b3f667d16a69e3ed99b2bed9e83f4f`인 설치 원본입니다. 정적 분석의 근거와 한계는 [분석 기록](ANALYSIS-26.10.0.md)을 참고하세요.

## 실행한 검증

- `python3 prepare_no_ad.py`: 설치 원본을 읽기만 하여 전체 및 arm64 해시, 세 수정 위치의 바이트, 수정 후 전체 해시를 검증했습니다. 수정 후 전체 해시는 `3ce9ce0e865fe96b5210a83c1825743b89583f66388a66ce4a480e7a4b443b4e`입니다.
- `bash scripts/build.sh`: 0.2.0 arm64 앱을 빌드하고 자체 서명을 검증했습니다.
- `"dist/카카오 광고 정리.app/Contents/MacOS/NoAdKakao" --self-test --source-app /Applications/KakaoTalk.app --legacy-source-app "$HOME/Library/Application Support/NoAdKakao/Backups/78947867aded66224b300660/Original.backup"`: 임시 복사본에서 새 버전의 적용, 동의 요구, 설치 전 실패 시 원본 보존, 서명 후 세 수정 위치 검증과 기존 서명 복구, 변조 백업 거부, 전체 원본 복원을 통과했습니다. 같은 대상 경로에 26.9 백업이 있어도 26.10 백업을 별도로 만들고 현재 버전을 복원하며 이전 백업과 기록이 보존됨을 확인했습니다.
- 같은 자체 테스트를 `--source-app`에 26.9 원본 백업을 지정해 실행하여 기존 schema 1 백업 경로의 적용·복구·복원을 확인했습니다.
- `bash scripts/test-loader.sh`: Hardened Runtime 임시 서명의 독립 라이브러리 로더 테스트에서 예상 출력값 `42`를 확인했습니다. 이는 테스트 건수가 아닙니다.
- `bash scripts/package-dmg.sh`: DMG 생성 및 `hdiutil verify` 통과. 기존 `hdiutil create` 사용에 대한 폐기 예정 경고가 출력됐습니다.
- `codesign --verify --deep --strict "dist/카카오 광고 정리.app"`: 통과.

패처 GUI 스모크 검사에서 빌드된 앱의 네이티브 창에 `카카오톡`, `적용 가능`, `26.10.0 (2010)`, `/Applications/KakaoTalk.app`이 표시되고 `백업하고 적용` 버튼이 활성화된 것을 확인했습니다. 적용·복구·복원 버튼은 누르지 않았으며 카카오톡도 실행하지 않았습니다. 이는 패처 UI 검사이며 패치된 카카오톡 화면 검사가 아닙니다.

최종 앱 실행 파일과 DMG의 해시는 아래 값과 일치했고, 테스트 전후 설치된 카카오톡 실행 파일 해시는 동일했습니다. 테스트 대상의 앱 교체는 임시 디렉터리에서만 수행했습니다.

## 결과물과 미검증 범위

- `dist/카카오 광고 정리.app/Contents/MacOS/NoAdKakao` SHA-256: `f1be4b515408d6df356a075c1e7fb6718df0a9767e9c2d4579e19407a2b82608`
- `dist/NoAdKakao-0.2.0-arm64.dmg` SHA-256: `29e8e4004c786e808fe3975cb1391681807776f3cb4fc4a8789a19075defb9e6`

26.10.0은 공통 국가 판정 함수 자체를 수정하지 않습니다. 두 광고 경로에서 해당 판정 호출과 부작용을 생략하고 배너 숨김 분기를 고정하므로 부작용 가능성이 남습니다. 26.9.0은 공통 국가 판정을 수정하므로 광고 외 기능에 영향을 줄 가능성이 있습니다. 실제 카카오톡 앱은 실행하거나 설치 위치에서 수정하지 않았습니다. 따라서 광고 영역의 실제 표시 변화, 사용자 계정 로그인과 전체 앱 동작은 검증하지 않았습니다. 앱과 DMG는 ad-hoc 서명이며 Apple 공증을 받지 않았습니다.
