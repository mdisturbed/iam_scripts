<#
.SYNOPSIS
    Point-and-click console for an engagement folder: pick scripts and run them, build the deliverables and the
    dashboard, and run the engagement's own actions, without typing commands.

.DESCRIPTION
    A Windows desktop window (WPF) over the same tools Start-Engagement.ps1 runs. Nothing about delivery is
    rebuilt per engagement: the console reads the engagement folder and its config, so a new engagement only
    needs New-Engagement.ps1 (the console offers to run it) and, optionally, its own config\actions.psd1.

    Discovery tab   every script in tools\discovery-catalog.psd1 with its latest run, worst dataset status, age,
                    and any status-register row for it (Script column). Tick scripts and press Run selected.
    Delivery tab    access request, readiness check, evidence package, KPI summary, draft findings, dashboard
                    (opened when built), and shortcuts to the engagement's folders and README.
    Actions tab     the engagement's own entries from config\actions.psd1 (see examples\actions.example.psd1),
                    for scripts that belong to one engagement only.

    Theme: light or dark. Auto (the default) follows the Windows app mode; the Theme button in the header
    cycles Auto, Dark, Light and the choice is kept in console.json.

    Every command runs in its own PowerShell window, so sign-in prompts, input-file prompts and output stay
    visible, and the console stays responsive. The command line is shown at the top of that window.

    The console itself only reads the engagement folder and the catalog. It writes only: its own
    settings file (%APPDATA%\IamEngagementKit\console.json: last engagement folder and domain controller per
    folder), what New-Engagement.ps1 creates when you choose to set a folder up, and config\actions.psd1 copied
    from the example when Edit actions file finds none. It launches windows with
    Start-Process, so Test-ReadOnly.ps1 reports it; that is expected for this launcher and is why it lives in
    tools\, not scripts\.

    Double-click tools\Start-EngagementConsole.cmd to open it, or run -CreateShortcut once for a desktop icon.

.PARAMETER EngagementPath
    Engagement folder to open. Default: the last one used; otherwise pick one with Open engagement...

.PARAMETER CreateShortcut
    Put an "Engagement console" shortcut on the desktop and exit.

.EXAMPLE
    .\tools\Start-EngagementConsole.ps1
.EXAMPLE
    .\tools\Start-EngagementConsole.ps1 -EngagementPath $env:USERPROFILE\IAM-Evidence
.EXAMPLE
    .\tools\Start-EngagementConsole.ps1 -CreateShortcut

.NOTES
    Version : 1.1.1
    Requires: Windows, Windows PowerShell 5.1 or PowerShell 7.x (WPF). Started by the .cmd in STA mode.
    Scopes  : none itself; each tool documents its own.
#>
[CmdletBinding()]
param(
    [string]$EngagementPath = '',
    [switch]$CreateShortcut
)

$ErrorActionPreference = 'Stop'
$ConsoleVersion = '1.1.1'
# Started from the .cmd the PowerShell window is hidden: show a start-up failure instead of closing silently
trap {
    $m = "The engagement console could not start:`n$($_.Exception.Message)"
    try { Add-Type -AssemblyName PresentationFramework; [void][System.Windows.MessageBox]::Show($m, 'Engagement console') } catch { Write-Host $m -ForegroundColor Red }
    exit 1
}
$Kit = Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'EngagementPaths.ps1')

if ($env:OS -ne 'Windows_NT') { throw 'The engagement console needs Windows (WPF). Use Start-Engagement.ps1 elsewhere.' }

# ------------------------------------------------------------------ shortcut
if ($CreateShortcut) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $lnk = Join-Path $desktop 'Engagement console.lnk'
    $sh = New-Object -ComObject WScript.Shell
    $s = $sh.CreateShortcut($lnk)
    $s.TargetPath = Join-Path $PSScriptRoot 'Start-EngagementConsole.cmd'
    $s.WorkingDirectory = $Kit
    $s.WindowStyle = 7
    $s.IconLocation = "$env:SystemRoot\System32\imageres.dll,109"
    $s.Description = 'Identity engagement console'
    $s.Save()
    Write-Host "Shortcut created: $lnk"
    return
}

# ------------------------------------------------------------------ STA guard
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $exe = [Diagnostics.Process]::GetCurrentProcess().Path
    $a = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    # A trailing backslash would escape the closing quote ("D:\x\" -> D:\x"): double it
    if ($EngagementPath) { $a += @('-EngagementPath', "`"$($EngagementPath -replace '\\$', '\\')`"") }
    Start-Process -FilePath $exe -ArgumentList $a -WindowStyle Hidden
    return
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, Microsoft.VisualBasic

# ------------------------------------------------------------------ settings
$settingsDir = Join-Path $env:APPDATA 'IamEngagementKit'
$settingsFile = Join-Path $settingsDir 'console.json'
function Read-Settings {
    $o = @{ LastEngagement = ''; Servers = @{}; Theme = 'Auto' }
    if (Test-Path -LiteralPath $settingsFile) {
        try {
            $j = Get-Content -LiteralPath $settingsFile -Raw | ConvertFrom-Json
            if ($j.LastEngagement) { $o.LastEngagement = [string]$j.LastEngagement }
            if ($j.Theme -in @('Auto', 'Light', 'Dark')) { $o.Theme = [string]$j.Theme }
            if ($j.Servers) { foreach ($p in $j.Servers.PSObject.Properties) { $o.Servers[$p.Name] = [string]$p.Value } }
        } catch { }
    }
    $o
}
function Save-Settings {
    if (-not (Test-Path -LiteralPath $settingsDir)) { New-Item -ItemType Directory -Path $settingsDir -Force | Out-Null }
    ([pscustomobject]@{ LastEngagement = $script:Settings.LastEngagement; Theme = $script:Settings.Theme; Servers = [pscustomobject]$script:Settings.Servers }) |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $settingsFile -Encoding UTF8
}
$script:Settings = Read-Settings

$catalog = @((Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'discovery-catalog.psd1')).Scripts)

# ------------------------------------------------------------------ launching
# Commands run in PowerShell 7 (pwsh) when it is installed: the Graph, Az, Exchange and AWS modules are usually
# installed there, and Windows PowerShell 5.1 (which the .cmd uses for the window itself) does not see them.
$script:Exe = [Diagnostics.Process]::GetCurrentProcess().Path
$pwshCmd = Get-Command pwsh.exe -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $pwshCmd) { $pf = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'; if (Test-Path -LiteralPath $pf) { $pwshCmd = Get-Item -LiteralPath $pf } }
if ($pwshCmd) { $script:Exe = $(if ($pwshCmd.Source) { $pwshCmd.Source } else { $pwshCmd.FullName }) }
$script:ShellName = $(if ($script:Exe -match 'pwsh\.exe$') { 'PowerShell 7' } else { 'Windows PowerShell 5.1' })
# PowerShell also treats the typographic quotes U+2018/2019/201A/201B as single quotes: double those too
function ConvertTo-Quoted([string]$s) { "'" + ($s -replace "['\u2018\u2019\u201A\u201B]", '$0$0') + "'" }

function Start-KitWindow {
    # Runs one script in a new PowerShell window with named arguments; returns the command line shown.
    param([string]$Title, [string]$ScriptPath, [System.Collections.IDictionary]$Arguments = @{}, [string[]]$Switches = @(), [string]$After = '')
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($k in $Arguments.Keys) {
        $v = $Arguments[$k]
        if ($null -eq $v -or "$v" -eq '') { continue }
        if ($v -is [array]) { $parts.Add("-$k " + ((@($v) | ForEach-Object { ConvertTo-Quoted "$_" }) -join ',')) }
        else { $parts.Add("-$k " + (ConvertTo-Quoted "$v")) }
    }
    foreach ($sw in $Switches) { if ($sw) { $parts.Add("-$sw") } }
    $call = '& ' + (ConvertTo-Quoted $ScriptPath) + ' ' + ($parts -join ' ')
    $cmd = @(
        "`$host.UI.RawUI.WindowTitle = $(ConvertTo-Quoted $Title)"
        "Set-Location -LiteralPath $(ConvertTo-Quoted $Kit)"
        "Write-Host $(ConvertTo-Quoted "> $call") -ForegroundColor DarkGray"
        # $After (e.g. open the dashboard) runs only when the call did not fail
        "try {$([Environment]::NewLine)$call$([Environment]::NewLine)$After$([Environment]::NewLine)} catch { Write-Host `$_.Exception.Message -ForegroundColor Red }"
        "Write-Host ''; Write-Host 'Finished. Close this window when you are done.' -ForegroundColor Cyan"
    ) -join [Environment]::NewLine
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    Start-Process -FilePath $script:Exe -ArgumentList @('-NoExit', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $b64) | Out-Null
    Set-Status "Started: $Title"
    $call
}

function Open-Path([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { [System.Windows.MessageBox]::Show("Not found:`n$Path", 'Engagement console') | Out-Null; return }
    # A file type with no associated program (often .md) opens in Notepad instead
    try { Start-Process -FilePath $Path | Out-Null } catch { Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$Path`"" | Out-Null }
}

# ------------------------------------------------------------------ UI
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Engagement console" Width="1240" Height="780" MinWidth="980" MinHeight="600"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13"
        Background="{DynamicResource WindowBg}" Foreground="{DynamicResource Fg}">
  <Window.Resources>
    <!-- Theme brushes: light values here; Set-Theme swaps them at run time (DynamicResource) -->
    <SolidColorBrush x:Key="WindowBg" Color="#F5F6F8"/>
    <SolidColorBrush x:Key="PanelBg" Color="#FFFFFF"/>
    <SolidColorBrush x:Key="PanelBorder" Color="#E1E4E8"/>
    <SolidColorBrush x:Key="CtrlBg" Color="#FFFFFF"/>
    <SolidColorBrush x:Key="CtrlBorder" Color="#C9CED6"/>
    <SolidColorBrush x:Key="CtrlHover" Color="#EEF2F7"/>
    <SolidColorBrush x:Key="Fg" Color="#1B1F24"/>
    <SolidColorBrush x:Key="FgMuted" Color="#5A6270"/>
    <SolidColorBrush x:Key="FgDim" Color="#7A828E"/>
    <SolidColorBrush x:Key="Accent" Color="#1F5FBF"/>
    <SolidColorBrush x:Key="AccentHover" Color="#1A51A3"/>
    <SolidColorBrush x:Key="AccentFg" Color="#FFFFFF"/>
    <SolidColorBrush x:Key="RowBad" Color="#FDECEC"/>
    <SolidColorBrush x:Key="RowWarn" Color="#FFF6E0"/>
    <SolidColorBrush x:Key="RowSelected" Color="#DCE8FA"/>
    <SolidColorBrush x:Key="GridLine" Color="#ECEEF1"/>
    <SolidColorBrush x:Key="HeaderBg" Color="#F7F8FA"/>

    <Style TargetType="TextBlock"><Setter Property="Foreground" Value="{DynamicResource Fg}"/></Style>
    <Style x:Key="Muted" TargetType="TextBlock"><Setter Property="Foreground" Value="{DynamicResource FgMuted}"/></Style>

    <Style TargetType="Button">
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="Background" Value="{DynamicResource CtrlBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource Fg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource CtrlBorder}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="{DynamicResource CtrlHover}"/></Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.5"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="{DynamicResource Accent}"/>
      <Setter Property="Foreground" Value="{DynamicResource AccentFg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Accent}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="1" CornerRadius="4" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="{DynamicResource AccentHover}"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Card" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Width" Value="270"/>
      <Setter Property="Height" Value="96"/>
      <Setter Property="Margin" Value="0,0,12,12"/>
      <Setter Property="Padding" Value="14,10"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="VerticalContentAlignment" Value="Top"/>
    </Style>

    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{DynamicResource CtrlBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource Fg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource CtrlBorder}"/>
      <Setter Property="CaretBrush" Value="{DynamicResource Fg}"/>
    </Style>

    <Style TargetType="TabControl">
      <Setter Property="Background" Value="{DynamicResource PanelBg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource PanelBorder}"/>
    </Style>
    <Style TargetType="TabItem">
      <Setter Property="Foreground" Value="{DynamicResource FgMuted}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="Bd" Background="Transparent" BorderBrush="Transparent" BorderThickness="0,0,0,2" Padding="14,8" Margin="0,0,2,0">
              <ContentPresenter ContentSource="Header" HorizontalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/>
                <Setter Property="Foreground" Value="{DynamicResource Fg}"/>
                <Setter Property="FontWeight" Value="SemiBold"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="{DynamicResource CtrlHover}"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="{DynamicResource PanelBg}"/>
      <Setter Property="RowBackground" Value="{DynamicResource PanelBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource Fg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource PanelBorder}"/>
      <Setter Property="HorizontalGridLinesBrush" Value="{DynamicResource GridLine}"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="{DynamicResource HeaderBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource FgMuted}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource PanelBorder}"/>
      <Setter Property="BorderThickness" Value="0,0,1,1"/>
      <Setter Property="Padding" Value="8,6"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="6,0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="Transparent" Padding="{TemplateBinding Padding}">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <DockPanel>
    <Border DockPanel.Dock="Top" Background="{DynamicResource PanelBg}" BorderBrush="{DynamicResource PanelBorder}" BorderThickness="0,0,0,1" Padding="18,14">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel>
          <TextBlock x:Name="EngName" Text="No engagement open" FontSize="20" FontWeight="SemiBold"/>
          <TextBlock x:Name="EngPath" Style="{StaticResource Muted}" Margin="0,2,0,0"/>
          <TextBlock x:Name="EvPath" Style="{StaticResource Muted}"/>
        </StackPanel>
        <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
          <TextBlock Text="Domain controller" VerticalAlignment="Center" Margin="0,0,8,0" Style="{StaticResource Muted}"/>
          <TextBox x:Name="Server" Width="220" Padding="4,4" Margin="0,0,8,0" VerticalContentAlignment="Center"/>
          <Button x:Name="SaveServer" Content="Save"/>
          <Button x:Name="OpenEng" Content="Open engagement..."/>
          <Button x:Name="NewEng" Content="New engagement..."/>
          <Button x:Name="ThemeBtn" Content="Theme: Auto" Margin="0" ToolTip="Auto follows the Windows app setting"/>
        </StackPanel>
      </Grid>
    </Border>
    <Border DockPanel.Dock="Bottom" Background="{DynamicResource PanelBg}" BorderBrush="{DynamicResource PanelBorder}" BorderThickness="0,1,0,0" Padding="18,6">
      <TextBlock x:Name="Status" Style="{StaticResource Muted}" TextTrimming="CharacterEllipsis"/>
    </Border>
    <TabControl Margin="14" Padding="12">
      <TabItem Header="Discovery">
        <DockPanel>
          <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,10">
            <Button x:Name="RunSel" Content="Run selected" Style="{StaticResource Primary}"/>
            <Button x:Name="SelNotRun" Content="Select not run"/>
            <Button x:Name="SelBlocked" Content="Select blocked / partial"/>
            <Button x:Name="SelNone" Content="Clear"/>
            <Button x:Name="Readiness" Content="Readiness check"/>
            <Button x:Name="Refresh" Content="Refresh"/>
            <TextBlock x:Name="Counts" VerticalAlignment="Center" Margin="8,0,0,0" Style="{StaticResource Muted}"/>
          </StackPanel>
          <DataGrid x:Name="Grid" AutoGenerateColumns="False" CanUserAddRows="False" CanUserDeleteRows="False"
                    HeadersVisibility="Column" GridLinesVisibility="Horizontal" RowHeight="28" SelectionMode="Extended">
            <DataGrid.Columns>
              <DataGridTemplateColumn Header="Run" Width="44" SortMemberPath="Run">
                <DataGridTemplateColumn.CellTemplate>
                  <DataTemplate>
                    <CheckBox IsChecked="{Binding Run, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                  </DataTemplate>
                </DataGridTemplateColumn.CellTemplate>
              </DataGridTemplateColumn>
              <DataGridTextColumn Header="#" Binding="{Binding Number}" IsReadOnly="True" Width="40"/>
              <DataGridTextColumn Header="Script" Binding="{Binding Title}" IsReadOnly="True" Width="230"/>
              <DataGridTextColumn Header="Area" Binding="{Binding Area}" IsReadOnly="True" Width="90"/>
              <DataGridTextColumn Header="Needs" Binding="{Binding Needs}" IsReadOnly="True" Width="130"/>
              <DataGridTextColumn Header="Last run (UTC)" Binding="{Binding LastRun}" IsReadOnly="True" Width="130"/>
              <DataGridTextColumn Header="Age (d)" Binding="{Binding AgeDays}" IsReadOnly="True" Width="60"/>
              <DataGridTextColumn Header="State" Binding="{Binding State}" IsReadOnly="True" Width="150"/>
              <DataGridTextColumn Header="Register note" Binding="{Binding Note}" IsReadOnly="True" Width="*"/>
            </DataGrid.Columns>
            <DataGrid.RowStyle>
              <Style TargetType="DataGridRow">
                <Setter Property="Background" Value="{DynamicResource PanelBg}"/>
                <Setter Property="Foreground" Value="{DynamicResource Fg}"/>
                <Style.Triggers>
                  <DataTrigger Binding="{Binding Tone}" Value="bad"><Setter Property="Background" Value="{DynamicResource RowBad}"/></DataTrigger>
                  <DataTrigger Binding="{Binding Tone}" Value="warn"><Setter Property="Background" Value="{DynamicResource RowWarn}"/></DataTrigger>
                  <DataTrigger Binding="{Binding Tone}" Value="mut"><Setter Property="Foreground" Value="{DynamicResource FgDim}"/></DataTrigger>
                  <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource RowSelected}"/></Trigger>
                </Style.Triggers>
              </Style>
            </DataGrid.RowStyle>
          </DataGrid>
        </DockPanel>
      </TabItem>
      <TabItem Header="Delivery">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel>
            <TextBlock Text="Build" FontWeight="SemiBold" Margin="0,0,0,8" Style="{StaticResource Muted}"/>
            <WrapPanel x:Name="BuildCards"/>
            <TextBlock Text="Open" FontWeight="SemiBold" Margin="0,8,0,8" Style="{StaticResource Muted}"/>
            <WrapPanel x:Name="OpenCards"/>
          </StackPanel>
        </ScrollViewer>
      </TabItem>
      <TabItem Header="Engagement actions">
        <DockPanel>
          <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,10">
            <Button x:Name="EditActions" Content="Edit actions file"/>
            <Button x:Name="ReloadActions" Content="Reload"/>
            <TextBlock x:Name="ActionsInfo" VerticalAlignment="Center" Style="{StaticResource Muted}"/>
          </StackPanel>
          <ScrollViewer VerticalScrollBarVisibility="Auto"><WrapPanel x:Name="ActionCards"/></ScrollViewer>
        </DockPanel>
      </TabItem>
    </TabControl>
  </DockPanel>
</Window>
'@
$window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
$window.Dispatcher.Add_UnhandledException({
        param($s, $e)
        [System.Windows.MessageBox]::Show("Something went wrong:`n$($e.Exception.Message)", 'Engagement console') | Out-Null
        $e.Handled = $true
    })
$ui = @{}
foreach ($n in 'EngName', 'EngPath', 'EvPath', 'Server', 'SaveServer', 'OpenEng', 'NewEng', 'Status', 'RunSel', 'SelNotRun', 'SelBlocked', 'SelNone',
    'Readiness', 'Refresh', 'Counts', 'Grid', 'BuildCards', 'OpenCards', 'EditActions', 'ReloadActions', 'ActionsInfo', 'ActionCards', 'ThemeBtn') {
    $ui[$n] = $window.FindName($n)
}
function Set-Status([string]$t) { $ui.Status.Text = "$((Get-Date).ToString('HH:mm:ss'))  $t" }

# ------------------------------------------------------------------ theme
# Light and dark palettes for the brushes in Window.Resources. Auto follows the Windows app setting
# (Settings > Personalization > Colors > app mode). Only the console's look changes; nothing on disk but the
# Theme value in console.json.
$script:Palettes = @{
    Light = @{ WindowBg = '#F5F6F8'; PanelBg = '#FFFFFF'; PanelBorder = '#E1E4E8'; CtrlBg = '#FFFFFF'; CtrlBorder = '#C9CED6'; CtrlHover = '#EEF2F7'
        Fg = '#1B1F24'; FgMuted = '#5A6270'; FgDim = '#7A828E'; Accent = '#1F5FBF'; AccentHover = '#1A51A3'; AccentFg = '#FFFFFF'
        RowBad = '#FDECEC'; RowWarn = '#FFF6E0'; RowSelected = '#DCE8FA'; GridLine = '#ECEEF1'; HeaderBg = '#F7F8FA' }
    Dark  = @{ WindowBg = '#16181C'; PanelBg = '#1E2127'; PanelBorder = '#2E333B'; CtrlBg = '#262A31'; CtrlBorder = '#3A4049'; CtrlHover = '#30353D'
        Fg = '#E6E8EB'; FgMuted = '#A0A7B2'; FgDim = '#7D8490'; Accent = '#3B82F6'; AccentHover = '#5A96F7'; AccentFg = '#FFFFFF'
        RowBad = '#3B2326'; RowWarn = '#3A3221'; RowSelected = '#24395C'; GridLine = '#2A2E35'; HeaderBg = '#23272D' }
}

function Test-WindowsDarkMode {
    try {
        $v = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name AppsUseLightTheme -ErrorAction Stop
        return ($v.AppsUseLightTheme -eq 0)
    } catch { return $false }
}

$script:DwmReady = $false
try {
    Add-Type -Namespace IamKit -Name Dwm -MemberDefinition '[DllImport("dwmapi.dll")] public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);' -ErrorAction Stop
    $script:DwmReady = $true
} catch { }

function Set-TitleBar([bool]$Dark) {
    # Dark title bar on Windows 10 2004+ / 11 (attribute 20; 19 on older builds). Cosmetic: failures are ignored.
    if (-not $script:DwmReady) { return }
    try {
        $hwnd = (New-Object System.Windows.Interop.WindowInteropHelper $window).Handle
        if ($hwnd -eq [IntPtr]::Zero) { return }
        $v = [int]$Dark
        if ([IamKit.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$v, 4) -ne 0) { [void][IamKit.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$v, 4) }
    } catch { }
}

function Set-Theme([string]$Mode) {
    $dark = $(switch ($Mode) { 'Dark' { $true } 'Light' { $false } default { Test-WindowsDarkMode } })
    $pal = $script:Palettes[$(if ($dark) { 'Dark' } else { 'Light' })]
    $conv = New-Object System.Windows.Media.BrushConverter
    foreach ($k in $pal.Keys) {
        $b = $conv.ConvertFromString($pal[$k]); $b.Freeze()
        $window.Resources[$k] = $b
    }
    $ui.ThemeBtn.Content = "Theme: $Mode"
    $script:IsDark = $dark
    Set-TitleBar $dark
}

$ui.ThemeBtn.Add_Click({
        $next = @{ Auto = 'Dark'; Dark = 'Light'; Light = 'Auto' }[$script:Settings.Theme]
        if (-not $next) { $next = 'Auto' }
        $script:Settings.Theme = $next
        Set-Theme $next
        Save-Settings
        Set-Status "Theme: $next$(if ($next -eq 'Auto') { ' (follows Windows)' })"
    })
$window.Add_SourceInitialized({ Set-TitleBar $script:IsDark })
Set-Theme $script:Settings.Theme

$table = New-Object System.Data.DataTable
foreach ($c in 'Number', 'Title', 'Area', 'Needs', 'LastRun', 'State', 'Note', 'Tone') { [void]$table.Columns.Add($c, [string]) }
[void]$table.Columns.Add('AgeDays', [int])   # numeric so the column sorts 9 before 10; empty = never run
[void]$table.Columns.Add('Run', [bool])
$ui.Grid.ItemsSource = $table.DefaultView

$script:P = $null

function Get-ServerValue { $ui.Server.Text.Trim() }

function New-Card {
    # A card button; the click handler gets its data from $this.Tag (no closures: handlers must see this script's scope).
    param($Panel, [string]$Title, [string]$Text, [scriptblock]$OnClick, $Tag = $null)
    $b = New-Object System.Windows.Controls.Button
    $b.Style = $window.FindResource('Card')
    $b.Tag = $Tag
    $sp = New-Object System.Windows.Controls.StackPanel
    $t1 = New-Object System.Windows.Controls.TextBlock; $t1.Text = $Title; $t1.FontWeight = [System.Windows.FontWeights]::SemiBold; $t1.FontSize = 14
    $t2 = New-Object System.Windows.Controls.TextBlock; $t2.Text = $Text; $t2.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $t2.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'FgMuted'); $t2.Margin = New-Object System.Windows.Thickness(0, 4, 0, 0); $t2.Width = 240
    [void]$sp.Children.Add($t1); [void]$sp.Children.Add($t2)
    $b.Content = $sp
    $b.Add_Click($OnClick)
    [void]$Panel.Children.Add($b)
}

function Assert-Engagement {
    if (-not $script:P) { [System.Windows.MessageBox]::Show('Open an engagement first.', 'Engagement console') | Out-Null; return $false }
    $true
}

function Update-Grid {
    $table.Rows.Clear()
    if (-not $script:P) { $ui.Counts.Text = ''; return }
    $states = @(Get-ScriptStates -Paths $script:P -Catalog $catalog)
    foreach ($s in $states) {
        $r = $table.NewRow()
        foreach ($c in 'Number', 'Title', 'Area', 'Needs', 'LastRun', 'State', 'Note') { $r[$c] = [string]$s.$c }
        if ("$($s.AgeDays)" -ne '') { $r['AgeDays'] = [int]$s.AgeDays }
        $r['Tone'] = $(switch -Wildcard ($s.State) { 'Blocked*' { 'bad' } 'Partial*' { 'warn' } 'EvidenceUnavailable*' { 'warn' } 'Deferred*' { 'mut' } 'Not run' { 'mut' } default { '' } })
        $r['Run'] = $false
        $table.Rows.Add($r)
    }
    $done = @($states | Where-Object { $_.State -eq 'Completed' }).Count
    $notRun = @($states | Where-Object { $_.State -eq 'Not run' }).Count
    $reg = @($states | Where-Object { $_.State -like '*(register)' }).Count
    $ui.Counts.Text = "$($states.Count) scripts: $done completed, $notRun not run, $reg recorded in the status register"
}

function Update-Actions {
    $ui.ActionCards.Children.Clear()
    if (-not $script:P) { return }
    $acts = @(Get-EngagementActions -Paths $script:P)
    $ui.ActionsInfo.Text = $(if ($acts.Count) { "$($acts.Count) action(s) from config\actions.psd1" }
        elseif (Test-Path -LiteralPath $script:P.Actions) { 'config\actions.psd1 lists no actions or could not be read (check it with Edit actions file).' }
        else { 'No config\actions.psd1 yet. Edit actions file creates one from the example.' })
    foreach ($a in $acts) {
        New-Card -Panel $ui.ActionCards -Title ([string]$a.Name) -Text ([string]$a.Description) -Tag $a -OnClick { Invoke-EngagementAction $this.Tag }
    }
}

function Invoke-EngagementAction($act) {
    $srv = Get-ServerValue
    $scr = Expand-EngagementToken -Text ([string]$act.Script) -Paths $script:P -Kit $Kit -Server $srv
    if (-not [IO.Path]::IsPathRooted($scr)) { $scr = Join-Path $Kit $scr }
    if (-not (Test-Path -LiteralPath $scr)) { [System.Windows.MessageBox]::Show("Script not found:`n$scr", 'Engagement console') | Out-Null; return }
    $args2 = [ordered]@{}
    if ($act.Arguments) { foreach ($k in $act.Arguments.Keys) { $args2[$k] = Expand-EngagementToken -Text ([string]$act.Arguments[$k]) -Paths $script:P -Kit $Kit -Server $srv } }
    [void](Start-KitWindow -Title ([string]$act.Name) -ScriptPath $scr -Arguments $args2 -Switches @($act.Switches))
}

function Open-Engagement([string]$Path) {
    $p = Get-EngagementPaths -EngagementPath $Path
    if (-not $p.IsEngagement) {
        $flat = @(Get-ChildItem -LiteralPath $p.Root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\d\d-' }).Count
        $msg = "This folder is not set up as an engagement yet:`n$($p.Root)`n`nSet it up now? This adds registers, config, findings, templates and reports folders and never overwrites a file."
        if ($flat) { $msg += "`n`nIt already holds $flat script folder(s), so they stay where they are and are used as the evidence." }
        if ([System.Windows.MessageBox]::Show($msg, 'Engagement console', 'YesNo', 'Question') -ne 'Yes') { return }
        $name = [Microsoft.VisualBasic.Interaction]::InputBox('Engagement name (used for page titles):', 'Engagement console', (Split-Path $p.Root -Leaf))
        if (-not $name) { return }
        $na = @{ Path = $p.Root; Name = $name; Force = $true }
        if ($flat) { $na['EvidencePath'] = '.' }
        try { & (Join-Path $PSScriptRoot 'New-Engagement.ps1') @na | Out-Null }
        catch { [System.Windows.MessageBox]::Show("New-Engagement failed:`n$($_.Exception.Message)", 'Engagement console') | Out-Null; return }
        $p = Get-EngagementPaths -EngagementPath $Path
    }
    $script:P = $p
    $script:Settings.LastEngagement = $p.Root
    Save-Settings
    $ui.EngName.Text = $p.Name
    $ui.EngPath.Text = "Folder: $($p.Root)"
    $ui.EvPath.Text = "Evidence: $($p.Evidence)"
    $ui.Server.Text = [string]$script:Settings.Servers[$p.Root]
    $window.Title = "Engagement console - $($p.Name)"
    Update-Grid
    Update-Actions
    Set-Status "Opened $($p.Name). Commands run in $script:ShellName."
}

function Select-Folder([string]$Description) {
    $d = New-Object System.Windows.Forms.FolderBrowserDialog
    $d.Description = $Description
    if ($script:P) { $d.SelectedPath = $script:P.Root }
    if ($d.ShowDialog() -eq 'OK') { return $d.SelectedPath }
    ''
}

# ------------------------------------------------------------------ Delivery cards
$tools = $PSScriptRoot
New-Card -Panel $ui.BuildCards -Title 'Access request' -Text 'Roles, Graph permissions, other access, inputs and licences for the client, into reports\.' -OnClick {
    if (-not (Assert-Engagement)) { return }
    [void](Start-KitWindow -Title 'Access request' -ScriptPath (Join-Path $tools 'New-AccessRequest.ps1') -Arguments ([ordered]@{ AuthMode = 'Delegated'; OutputRoot = $script:P.Reports }))
}
New-Card -Panel $ui.BuildCards -Title 'Evidence package' -Text 'Intake log, hash re-check and per-deliverable status for every run.' -OnClick {
    if (-not (Assert-Engagement)) { return }
    [void](Start-KitWindow -Title 'Evidence package' -ScriptPath (Join-Path $tools 'New-EvidencePackage.ps1') -Arguments ([ordered]@{ EvidenceRoot = $script:P.Evidence; DeliverableMapPath = (Join-Path $script:P.Config 'deliverable-map.psd1') }))
}
New-Card -Panel $ui.BuildCards -Title 'KPI summary' -Text 'KPI values over the script 27 denominators, from config\kpi-definitions.psd1.' -OnClick {
    if (-not (Assert-Engagement)) { return }
    [void](Start-KitWindow -Title 'KPI summary' -ScriptPath (Join-Path $tools 'Get-KpiSummary.ps1') -Arguments ([ordered]@{ EvidenceRoot = $script:P.Evidence; KpiDefinitionPath = (Join-Path $script:P.Config 'kpi-definitions.psd1') }))
}
New-Card -Panel $ui.BuildCards -Title 'Draft findings' -Text 'New findings from the latest runs, ready to paste into the review workbook.' -OnClick {
    if (-not (Assert-Engagement)) { return }
    $a = [ordered]@{ EvidenceRoot = $script:P.Evidence; LedgerPath = (Join-Path $script:P.Findings 'finding-ledger.csv'); OutputRoot = $script:P.Reports }
    $rules = Join-Path $script:P.Config 'finding-rules.psd1'; if (Test-Path -LiteralPath $rules) { $a['RulesPath'] = $rules }
    $trail = Join-Path $script:P.Findings 'findings-review.csv'; if (Test-Path -LiteralPath $trail) { $a['ReviewTrailCsv'] = $trail }
    [void](Start-KitWindow -Title 'Draft findings' -ScriptPath (Join-Path $tools 'New-FindingDrafts.ps1') -Arguments $a)
}
New-Card -Panel $ui.BuildCards -Title 'Dashboard' -Text 'Runs, KPIs, readiness, findings and open items on one page. Opens when built.' -OnClick {
    if (-not (Assert-Engagement)) { return }
    $a = [ordered]@{ EvidenceRoot = $script:P.Evidence; OutputRoot = $script:P.Reports; Title = "$($script:P.Name) dashboard" }
    $ready = Join-Path $script:P.Registers 'readiness-checklist.csv'; if (Test-Path -LiteralPath $ready) { $a['ReadinessCsv'] = $ready }
    $status = Join-Path $script:P.Registers 'status-register.csv'; if (Test-Path -LiteralPath $status) { $a['StatusRegisterCsv'] = $status }
    $find = Join-Path $script:P.Findings 'findings-review.csv'; if (Test-Path -LiteralPath $find) { $a['FindingsCsv'] = $find }
    $dash = Join-Path $script:P.Reports 'New-EngagementDashboard'
    $after = "`$h = Get-ChildItem -LiteralPath $(ConvertTo-Quoted $dash) -Recurse -Filter engagement-dashboard.html -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1; if (`$h) { Invoke-Item -LiteralPath `$h.FullName }"
    [void](Start-KitWindow -Title 'Dashboard' -ScriptPath (Join-Path $tools 'New-EngagementDashboard.ps1') -Arguments $a -After $after)
}
New-Card -Panel $ui.OpenCards -Title 'Latest dashboard' -Text 'Open the most recent dashboard without rebuilding it.' -OnClick {
    if (-not (Assert-Engagement)) { return }
    $h = Get-ChildItem -LiteralPath (Join-Path $script:P.Reports 'New-EngagementDashboard') -Recurse -Filter engagement-dashboard.html -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
    if ($h) { Open-Path $h.FullName } else { [System.Windows.MessageBox]::Show('No dashboard yet. Use Dashboard to build one.', 'Engagement console') | Out-Null }
}
foreach ($f in @(@('Evidence folder', 'Run folders of the scripts and tools.', 'Evidence'), @('Registers', 'Readiness checklist, status register and input files.', 'Registers'),
        @('Findings', 'Evidence notes, ledger and the review workbook.', 'Findings'), @('Reports', 'Access requests, finding drafts and dashboards.', 'Reports'),
        @('Config', 'KPI definitions, deliverable map, finding rules, actions.', 'Config'), @('README', 'Run order and commands for this folder.', 'Readme'))) {
    New-Card -Panel $ui.OpenCards -Title $f[0] -Text $f[1] -Tag $f[2] -OnClick { if (Assert-Engagement) { Open-Path $script:P.($this.Tag) } }
}

# ------------------------------------------------------------------ Discovery buttons
$ui.RunSel.Add_Click({
        if (-not (Assert-Engagement)) { return }
        $sel = @($table.Rows | Where-Object { $_['Run'] -eq $true } | ForEach-Object { [string]$_['Number'] })
        if (-not $sel.Count) { [System.Windows.MessageBox]::Show('Tick the scripts to run in the Run column first.', 'Engagement console') | Out-Null; return }
        $a = [ordered]@{ OutputRoot = $script:P.Evidence; Select = $sel; Server = (Get-ServerValue) }
        [void](Start-KitWindow -Title "Discovery: $($sel -join ', ')" -ScriptPath (Join-Path $tools 'Start-Discovery.ps1') -Arguments $a)
    })
$ui.Readiness.Add_Click({
        if (-not (Assert-Engagement)) { return }
        [void](Start-KitWindow -Title 'Readiness check' -ScriptPath (Join-Path $tools 'Start-Discovery.ps1') -Arguments ([ordered]@{ OutputRoot = $script:P.Evidence; Server = (Get-ServerValue) }) -Switches @('ListOnly'))
    })
function Set-Ticks([scriptblock]$Where) { foreach ($r in $table.Rows) { $r['Run'] = [bool](& $Where $r) } }
$ui.SelNotRun.Add_Click({ Set-Ticks { param($r) $r['State'] -eq 'Not run' } })
$ui.SelBlocked.Add_Click({ Set-Ticks { param($r) $r['State'] -like 'Blocked*' -or $r['State'] -like 'Partial*' } })
$ui.SelNone.Add_Click({ Set-Ticks { param($r) $false } })
$ui.Refresh.Add_Click({ if ($script:P) { $script:P = Get-EngagementPaths -EngagementPath $script:P.Root; Update-Grid; Update-Actions; Set-Status 'Refreshed' } })

# ------------------------------------------------------------------ header buttons
$ui.SaveServer.Add_Click({
        if (-not (Assert-Engagement)) { return }
        $script:Settings.Servers[$script:P.Root] = Get-ServerValue; Save-Settings; Set-Status 'Domain controller saved for this engagement'
    })
$ui.OpenEng.Add_Click({ $f = Select-Folder 'Choose the engagement folder'; if ($f) { Open-Engagement $f } })
$ui.NewEng.Add_Click({
        $f = Select-Folder 'Choose or create an empty folder for the new engagement (outside the iam_scripts folder)'
        if ($f) { Open-Engagement $f }
    })
$ui.EditActions.Add_Click({
        if (-not (Assert-Engagement)) { return }
        if (-not (Test-Path -LiteralPath $script:P.Actions)) {
            [System.IO.File]::Copy((Join-Path $Kit 'examples\actions.example.psd1'), $script:P.Actions, $false)
        }
        Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$($script:P.Actions)`"" | Out-Null
    })
$ui.ReloadActions.Add_Click({ Update-Actions })

# ------------------------------------------------------------------ start
$start = $(if ($EngagementPath) { $EngagementPath } else { $script:Settings.LastEngagement })
$window.Add_ContentRendered({
        if ($start -and (Test-Path -LiteralPath $start)) { Open-Engagement $start }
        else { Set-Status "Engagement console $ConsoleVersion. Open an engagement folder, or create a new one." }
        $ui.Status.Text += "   |   Commands run in $script:ShellName"
    })
[void]$window.ShowDialog()
