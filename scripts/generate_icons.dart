import 'dart:io';

Future<void> main() async {
  if (!Platform.isWindows) {
    stderr.writeln('Run scripts/generate_icons.ps1 on Windows.');
    exitCode = 64;
    return;
  }

  final result = await Process.start('powershell', const [
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    'scripts/generate_icons.ps1',
  ], mode: ProcessStartMode.inheritStdio);
  exitCode = await result.exitCode;
}
