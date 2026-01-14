#define MyAppName "QuantumAuth"
#define MyAppExeName "quantumauth.exe"
#define MyAppPublisher "quantumauth-io"
#define MyAppURL "https://quantumauth.io"

; These are provided by CI via /DMyAppVersion=... /DMyAppSourceDir=...
#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif

#ifndef MyAppSourceDir
  ; fallback for local testing
  #define MyAppSourceDir "..\..\dist\windows-amd64"
#endif

; --- sanitize version for filenames ---
#define _Ver0 StringChange(MyAppVersion, '"', '')
#if Copy(_Ver0, 1, 1) == "v"
  #define MyAppVersionClean Copy(_Ver0, 2)
#else
  #define MyAppVersionClean _Ver0
#endif

; Only allow filename-safe chars: replace dots/spaces with underscores
#define MyAppVersionFile StringChange(MyAppVersionClean, ".", "_")
#define MyAppVersionFile StringChange(MyAppVersionFile, " ", "_")
; --------------------------------------

#pragma message "MyAppVersion=" + MyAppVersion
#pragma message "MyAppVersionClean=" + MyAppVersionClean
#pragma message "MyAppVersionFile=" + MyAppVersionFile

[Setup]
AppId={{A2D6B6D7-6C7C-4E64-9D3B-9F9C5C9A2A11}
AppName={#MyAppName}
AppVersion={#MyAppVersionClean}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
Compression=lzma
SolidCompression=yes
OutputBaseFilename=QuantumAuth-Setup-x64
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#MyAppSourceDir}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

; Add install dir to PATH (system-wide)
[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
  ValueType: expandsz; ValueName: "Path"; \
  ValueData: "{olddata};{app}"; \
  Check: NeedsAddPath(ExpandConstant('{app}')); \
  Flags: preservestringtype

[Code]
function NeedsAddPath(NewPath: string): Boolean;
var
  Path: string;
begin
  if not RegQueryStringValue(HKLM,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', Path) then
  begin
    Result := True;
    exit;
  end;

  // naive contains check is ok here; keep it simple
  Result := Pos(';' + Lowercase(NewPath) + ';', ';' + Lowercase(Path) + ';') = 0;
end;
