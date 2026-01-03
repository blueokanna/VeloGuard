import { FlutterPage, FlutterEntry } from '@aspect/flutter_ohos';

/**
 * Main entry page for CatClash on HarmonyOS NEXT
 * 
 * This page hosts the Flutter application.
 */
@Entry
@Component
struct Index {
  private flutterEntry: FlutterEntry = new FlutterEntry();

  aboutToAppear(): void {
    this.flutterEntry.aboutToAppear();
  }

  aboutToDisappear(): void {
    this.flutterEntry.aboutToDisappear();
  }

  build() {
    Column() {
      FlutterPage({ viewId: this.flutterEntry.getViewId() })
    }
    .width('100%')
    .height('100%')
  }
}
