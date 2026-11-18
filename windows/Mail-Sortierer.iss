; Postwart (früher Mail-Sortierer) – Windows-Setup. Sichtbarer Name Postwart; Ordner, Dienst-ID, Firewall-Regel bleiben technisch „Mail-Sortierer“ (Inno Setup 6). Baut die GitHub Action (Job „windows“ in .github/workflows/docker.yml):
; windows/build.ps1 legt Node.js, Programm und Dienst-Wrapper (WinSW) unter windows\build ab, danach
;   iscc /DAppVersion=… /DAppBuild=… /DAppCommit=… windows\Mail-Sortierer.iss
; Programm: C:\Program Files\Mail-Sortierer, Daten: C:\ProgramData\Mail-Sortierer (bleiben bei Update und – auf Wunsch – bei Deinstallation).

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef AppBuild
  #define AppBuild ""
#endif
#ifndef AppCommit
  #define AppCommit ""
#endif

[Setup]
AppId={{4E1C7B2A-93D5-4C1E-8A6F-2B7D9E0F3A51}
AppName=Postwart
AppVersion={#AppVersion}
AppVerName=Postwart {#AppVersion}
AppPublisher=Vedly
AppPublisherURL=https://vedly.de
AppSupportURL=https://vedly.de
VersionInfoVersion={#AppVersion}
VersionInfoDescription=Postwart Setup
DefaultDirName={autopf}\Mail-Sortierer
DefaultGroupName=Postwart
DisableProgramGroupPage=yes
OutputDir=..\dist-windows
OutputBaseFilename=Postwart-Setup-{#AppVersion}
SetupIconFile=mail-sortierer.ico
UninstallDisplayIcon={app}\mail-sortierer.ico
UninstallDisplayName=Postwart
WizardSmallImageFile=wizard-s100.bmp,wizard-s150.bmp,wizard-s200.bmp
WizardImageFile=wizard-l100.bmp,wizard-l150.bmp,wizard-l200.bmp
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
MinVersion=10.0
WizardStyle=modern
CloseApplications=no
RestartApplications=no

[Languages]
Name: "de"; MessagesFile: "compiler:Languages\German.isl"

[Tasks]
Name: "scan"; Description: "Scanner-Ordner für Rechnungen verwenden (Ordner im nächsten Schritt wählen)"
Name: "firewall"; Description: "Zugriff von anderen PCs im Firmennetz erlauben (Windows-Firewall)"; Flags: unchecked
Name: "desktopicon"; Description: "Verknüpfung auf dem Desktop anlegen"

[Dirs]
Name: "{commonappdata}\Mail-Sortierer"; Flags: uninsneveruninstall
Name: "{commonappdata}\Mail-Sortierer\data"; Flags: uninsneveruninstall
Name: "{commonappdata}\Mail-Sortierer\logs"; Flags: uninsneveruninstall

[Files]
Source: "build\node\*"; DestDir: "{app}\node"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "build\app\*"; DestDir: "{app}\app"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "build\Mail-Sortierer-Dienst.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "notfall-zugang.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "mail-sortierer.ico"; DestDir: "{app}"; Flags: ignoreversion

[INI]
Filename: "{app}\Postwart.url"; Section: "InternetShortcut"; Key: "URL"; String: "http://localhost:{code:GetPort}/"
Filename: "{app}\Postwart.url"; Section: "InternetShortcut"; Key: "IconFile"; String: "{app}\mail-sortierer.ico"
Filename: "{app}\Postwart.url"; Section: "InternetShortcut"; Key: "IconIndex"; String: "0"

[Icons]
Name: "{group}\Postwart öffnen"; Filename: "{app}\Postwart.url"; IconFilename: "{app}\mail-sortierer.ico"
Name: "{group}\Daten-Ordner"; Filename: "{commonappdata}\Mail-Sortierer"
Name: "{group}\Notfall-Zugang (Passwort vergessen)"; Filename: "{app}\notfall-zugang.cmd"; IconFilename: "{app}\mail-sortierer.ico"
Name: "{group}\Postwart deinstallieren"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Postwart"; Filename: "{app}\Postwart.url"; IconFilename: "{app}\mail-sortierer.ico"; Tasks: desktopicon

[Run]
Filename: "{sys}\ie4uinit.exe"; Parameters: "-show"; Flags: runhidden skipifdoesntexist
Filename: "https://ollama.com/download/windows"; Description: "Downloadseite von „Ollama für Windows“ öffnen (lokale KI – nötig, falls noch nicht installiert)"; Flags: shellexec postinstall skipifsilent nowait unchecked
Filename: "{app}\Postwart.url"; Description: "Postwart jetzt im Browser öffnen"; Flags: shellexec postinstall skipifsilent nowait

[UninstallRun]
Filename: "{app}\Mail-Sortierer-Dienst.exe"; Parameters: "stop"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{app}\Mail-Sortierer-Dienst.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Mail-Sortierer"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveFirewall"

[InstallDelete]
; Alte Verknüpfungen aus der Zeit als „Mail-Sortierer“
Type: files; Name: "{app}\Mail-Sortierer.url"
Type: filesandordirs; Name: "{autoprograms}\Mail-Sortierer"
Type: files; Name: "{autodesktop}\Mail-Sortierer.lnk"

[UninstallDelete]
Type: files; Name: "{app}\Postwart.url"
Type: files; Name: "{app}\Mail-Sortierer.url"
Type: files; Name: "{app}\Mail-Sortierer-Dienst.xml"
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\node"

[Code]
var
  PortPage: TInputQueryWizardPage;
  ScanPage: TInputDirWizardPage;

function DataDir(): String;
begin
  Result := ExpandConstant('{commonappdata}\Mail-Sortierer');
end;

function ServiceExe(): String;
begin
  Result := ExpandConstant('{app}\Mail-Sortierer-Dienst.exe');
end;

function GetPort(Param: String): String;
begin
  Result := Trim(PortPage.Values[0]);
end;

function GetScanDir(): String;
begin
  Result := '';
  if WizardIsTaskSelected('scan') then
    Result := Trim(ScanPage.Values[0]);
end;

procedure InitializeWizard();
begin
  PortPage := CreateInputQueryPage(wpSelectDir, 'Anschluss (Port)',
    'Unter welcher Adresse soll Postwart erreichbar sein?',
    'Postwart läuft als Windows-Dienst und wird im Browser geöffnet: http://localhost:<Port>. ' +
    'Nur ändern, wenn der Port auf diesem PC schon von einem anderen Programm genutzt wird.');
  PortPage.Add('Port:', False);
  PortPage.Values[0] := GetPreviousData('Port', '8110');

  ScanPage := CreateInputDirPage(wpSelectTasks, 'Scanner-Ordner',
    'In welchen Ordner legt Ihr Scanner die PDF-Dateien?',
    'Postwart holt Rechnungen von dort ab, legt sie nach Jahr und Monat im Rechnungs-Postfach ab und verschiebt die Datei danach nach „erledigt“ – gelöscht wird nichts.' + #13#10 +
    'Netzwerkordner bitte als \\Server\Freigabe angeben (Laufwerksbuchstaben sieht der Dienst nicht) und Benutzer/Passwort später unter Einstellungen → Rechnungen eintragen.',
    False, '');
  ScanPage.Add('Scanner-Ordner:');
  ScanPage.Values[0] := GetPreviousData('ScanDir', ExpandConstant('{sd}\Scans'));
end;

procedure RegisterPreviousData(PreviousDataKey: Integer);
begin
  SetPreviousData(PreviousDataKey, 'Port', GetPort(''));
  SetPreviousData(PreviousDataKey, 'ScanDir', ScanPage.Values[0]);
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = ScanPage.ID) and not WizardIsTaskSelected('scan');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  N: Integer;
begin
  Result := True;
  if CurPageID = PortPage.ID then
  begin
    N := StrToIntDef(GetPort(''), 0);
    if (N < 1024) or (N > 65535) then
    begin
      MsgBox('Bitte eine Zahl zwischen 1024 und 65535 eingeben.', mbError, MB_OK);
      Result := False;
    end;
  end;
  if (CurPageID = ScanPage.ID) and (Trim(ScanPage.Values[0]) = '') then
  begin
    MsgBox('Bitte einen Ordner wählen – oder einen Schritt zurück und „Scanner-Ordner verwenden“ abwählen.', mbError, MB_OK);
    Result := False;
  end;
end;

function RunService(Cmd: String): Integer;
var
  Code: Integer;
begin
  Code := -1;
  if FileExists(ServiceExe()) then
    Exec(ServiceExe(), Cmd, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code);
  Result := Code;
end;

function ServiceRunning(): Boolean;
var
  Code: Integer;
begin
  Result := Exec(ExpandConstant('{cmd}'), '/c tasklist /NH /FI "IMAGENAME eq Mail-Sortierer-Dienst.exe" | find /I "Mail-Sortierer-Dienst.exe" >nul',
    '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

{ Nach „stop“ hält der Dienst seine EXE oft noch kurz gesperrt – warten (max. 20 s), nach 10 s hart beenden. }
procedure WaitServiceExeFree();
var
  I, Code: Integer;
begin
  if not FileExists(ServiceExe()) then Exit;
  for I := 1 to 40 do
  begin
    if not ServiceRunning() then
    begin
      Sleep(500);
      Exit;
    end;
    if I = 20 then
      Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM Mail-Sortierer-Dienst.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
    Sleep(500);
  end;
end;

{ Vor dem Drüber-Installieren: Dienst anhalten und die Datenbank sichern. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Db, Target: String;
begin
  Result := '';
  RunService('stop');
  WaitServiceExeFree();
  Db := DataDir() + '\data\mail-sortierer.sqlite';
  if FileExists(Db) then
  begin
    Target := DataDir() + '\update-sicherungen\vor-' + '{#AppVersion}' + '-' + GetDateTimeString('yyyy-mm-dd-hhnnss', '-', '-');
    if not ForceDirectories(Target) or not FileCopy(Db, Target + '\mail-sortierer.sqlite', False) then
    begin
      Result := 'Die Datenbank konnte vor dem Update nicht gesichert werden. Das Setup wurde abgebrochen, an den Daten wurde nichts verändert.';
      RunService('start');
      Exit;
    end;
    if FileExists(Db + '-wal') then FileCopy(Db + '-wal', Target + '\mail-sortierer.sqlite-wal', False);
  end;
end;

function XmlEsc(S: String): String;
begin
  Result := S;
  StringChangeEx(Result, '&', '&amp;', True);
  StringChangeEx(Result, '<', '&lt;', True);
  StringChangeEx(Result, '>', '&gt;', True);
  StringChangeEx(Result, '"', '&quot;', True);
end;

function EnvLine(Name, Value: String): String;
begin
  Result := '  <env name="' + Name + '" value="' + XmlEsc(Value) + '"/>';
end;

procedure WriteServiceConfig();
var
  L: TArrayOfString;
begin
  SetArrayLength(L, 21);
  L[0] := '<service>';
  L[1] := '  <id>Mail-Sortierer</id>';
  L[2] := '  <name>Postwart</name>';
  L[3] := '  <description>Postwart – sortiert Postfächer mit lokaler KI (http://localhost:' + GetPort('') + ')</description>';
  L[4] := '  <executable>%BASE%\node\node.exe</executable>';
  L[5] := '  <arguments>--no-warnings "%BASE%\app\src\index.js"</arguments>';
  L[6] := '  <workingdirectory>%BASE%\app</workingdirectory>';
  L[7] := EnvLine('NODE_ENV', 'production');
  L[8] := EnvLine('PORT', GetPort(''));
  L[9] := EnvLine('DATA_DIR', DataDir() + '\data');
  L[10] := EnvLine('APP_VERSION', '{#AppVersion}');
  L[11] := EnvLine('APP_PLATFORM', 'windows');
  L[12] := EnvLine('SCAN_DIR', GetScanDir());
  L[13] := '  <logpath>' + XmlEsc(DataDir() + '\logs') + '</logpath>';
  L[14] := '  <log mode="roll-by-size"><sizeThreshold>10240</sizeThreshold><keepFiles>5</keepFiles></log>';
  L[15] := '  <onfailure action="restart" delay="10 sec"/>';
  L[16] := '  <onfailure action="restart" delay="30 sec"/>';
  L[17] := '  <resetfailure>1 hour</resetfailure>';
  L[18] := '  <startmode>Automatic</startmode>';
  L[19] := '  <stoptimeout>20 sec</stoptimeout>';
  L[20] := '</service>';
  SaveStringsToUTF8File(ExpandConstant('{app}\Mail-Sortierer-Dienst.xml'), L, False);
end;

procedure SetupFirewall();
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule name="Mail-Sortierer"', '', SW_HIDE, ewWaitUntilTerminated, Code);
  if WizardIsTaskSelected('firewall') then
    Exec(ExpandConstant('{sys}\netsh.exe'),
      'advfirewall firewall add rule name="Mail-Sortierer" dir=in action=allow protocol=TCP localport=' + GetPort('') + ' profile=private,domain',
      '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure Icacls(Params: String);
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\icacls.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Code);
  Log('icacls ' + Params + ' -> ' + IntToStr(Code));
end;

{ Datenordner nur für SYSTEM + Administratoren (Postfach-Passwörter, Mails, Belege). SIDs statt Namen (jede Windows-Sprache). }
procedure SecureDataDir();
var
  D: String;
begin
  D := DataDir();
  Icacls('"' + D + '" /setowner *S-1-5-32-544 /T /C /Q');
  Icacls('"' + D + '" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F /C /Q');
  Icacls('"' + D + '\*" /reset /T /C /Q');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    { lokaler Scan-Ordner: anlegen, falls es ihn noch nicht gibt }
    if (GetScanDir() <> '') and (Copy(GetScanDir(), 1, 2) <> '\\') then
      ForceDirectories(GetScanDir());
    WriteServiceConfig();
    RunService('stop');
    RunService('uninstall');
    SecureDataDir();
    if RunService('install') <> 0 then
      SuppressibleMsgBox('Der Windows-Dienst „Postwart“ konnte nicht eingerichtet werden. Bitte das Setup erneut als Administrator ausführen.', mbError, MB_OK, IDOK);
    RunService('start');
    SetupFirewall();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if DirExists(DataDir()) then
    begin
      if SuppressibleMsgBox('Postwart wurde entfernt.' + #13#10#13#10 +
        'Die Daten (Einstellungen, Gelerntes, Rechnungsbelege) liegen weiterhin unter' + #13#10 + DataDir() + #13#10#13#10 +
        'Sollen diese Daten ENDGÜLTIG gelöscht werden? Ihre Mails im Postfach bleiben in jedem Fall unverändert.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES then
      begin
        if SuppressibleMsgBox('Wirklich alle Daten von Postwart unwiderruflich löschen?', mbError, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES then
          DelTree(DataDir(), True, True, True);
      end;
    end;
  end;
end;
