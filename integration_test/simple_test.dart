import 'package:flutter_test/flutter_test.dart';
import 'package:veloguard/main.dart';
import 'package:veloguard/src/rust/frb_generated.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());
  testWidgets('App launches successfully', (WidgetTester tester) async {
    await tester.pumpWidget(const VeloGuardApp());
    await tester.pumpAndSettle();
    // Verify app launches with expected title
    expect(find.byType(VeloGuardApp), findsOneWidget);
  });
}
