import 'dart:io';

void main() async {
  print('VeloGuard Icon Generator');
  print('========================\n');

  // Check if SVG exists
  final svgFile = File('assets/veloguard.svg');
  if (!svgFile.existsSync()) {
    print('❌ Error: assets/veloguard.svg not found!');
    exit(1);
  }
  print('✓ Found assets/veloguard.svg');

  // Check if PNG exists
  final pngFile = File('assets/veloguard_icon.png');
  if (!pngFile.existsSync()) {
    print('\n⚠️  PNG icon not found!');
    print('\nPlease convert the SVG to PNG first:');
    print('1. Use an online tool: https://svgtopng.com/');
    print('2. Upload assets/veloguard.svg');
    print('3. Set size to 1024x1024');
    print('4. Download and save as assets/veloguard_icon.png');
    print('\nOr use ImageMagick:');
    print(
      '  magick convert -background none -size 1024x1024 assets/veloguard.svg assets/veloguard_icon.png',
    );
    exit(1);
  }
  print('✓ Found assets/veloguard_icon.png');

  // Check file size
  final fileSize = pngFile.lengthSync();
  print('  Size: ${(fileSize / 1024).toStringAsFixed(1)} KB');

  print('\n✓ Ready to generate icons!');
  print('\nRun the following command:');
  print('  dart run flutter_launcher_icons');
}
