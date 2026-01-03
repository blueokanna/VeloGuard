import { FlutterPlugin, MethodChannel, MethodCall, MethodResult } from '@aspect/flutter_ohos';
import { common, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { deviceInfo } from '@kit.BasicServicesKit';

const TAG = 'CatClashPlugin';
const DOMAIN = 0x0000;

/**
 * CatClash Flutter Plugin for HarmonyOS NEXT
 * 
 * This plugin provides the method channel interface between Flutter and native OHOS code.
 */
export class CatClashPlugin implements FlutterPlugin {
  private channel: MethodChannel | null = null;
  private context: common.UIAbilityContext | null = null;
  private isVpnRunning: boolean = false;
  private currentProxyMode: string = 'rule';

  onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding): void {
    this.context = binding.getApplicationContext() as common.UIAbilityContext;
    this.channel = new MethodChannel(binding.getBinaryMessenger(), 'com.catclash/ohos_proxy');
    
    this.channel.setMethodCallHandler({
      onMethodCall: (call: MethodCall, result: MethodResult) => {
        this.handleMethodCall(call, result);
      }
    });
    
    hilog.info(DOMAIN, TAG, 'CatClash plugin attached to engine');
  }

  onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding): void {
    this.channel?.setMethodCallHandler(null);
    this.channel = null;
    this.context = null;
    hilog.info(DOMAIN, TAG, 'CatClash plugin detached from engine');
  }

  private handleMethodCall(call: MethodCall, result: MethodResult): void {
    hilog.info(DOMAIN, TAG, 'Method call: %{public}s', call.method);
    
    switch (call.method) {
      case 'startVpn':
        this.startVpn(call, result);
        break;
      case 'stopVpn':
        this.stopVpn(result);
        break;
      case 'isVpnRunning':
        result.success(this.isVpnRunning);
        break;
      case 'setProxyMode':
        this.setProxyMode(call, result);
        break;
      case 'getVpnConnectionCount':
        result.success(0); // TODO: Implement connection counting
        break;
      case 'getDeviceInfo':
        this.getDeviceInfo(result);
        break;
      default:
        result.notImplemented();
    }
  }

  private async startVpn(call: MethodCall, result: MethodResult): Promise<void> {
    try {
      const mode = call.argument<string>('mode') || 'rule';
      this.currentProxyMode = mode;
      
      hilog.info(DOMAIN, TAG, 'Starting VPN with mode: %{public}s', mode);
      
      // Start VPN extension
      const want: Want = {
        bundleName: 'com.blueokanna.catclash',
        abilityName: 'CatClashVpnExtension',
        parameters: {
          action: 'start',
          mode: mode
        }
      };
      
      await this.context?.startAbility(want);
      this.isVpnRunning = true;
      result.success(true);
    } catch (error) {
      hilog.error(DOMAIN, TAG, 'Failed to start VPN: %{public}s', JSON.stringify(error));
      result.error('VPN_START_ERROR', 'Failed to start VPN', error);
    }
  }

  private async stopVpn(result: MethodResult): Promise<void> {
    try {
      hilog.info(DOMAIN, TAG, 'Stopping VPN');
      
      // Stop VPN extension
      const want: Want = {
        bundleName: 'com.blueokanna.catclash',
        abilityName: 'CatClashVpnExtension',
        parameters: {
          action: 'stop'
        }
      };
      
      await this.context?.startAbility(want);
      this.isVpnRunning = false;
      result.success(true);
    } catch (error) {
      hilog.error(DOMAIN, TAG, 'Failed to stop VPN: %{public}s', JSON.stringify(error));
      result.error('VPN_STOP_ERROR', 'Failed to stop VPN', error);
    }
  }

  private setProxyMode(call: MethodCall, result: MethodResult): void {
    const mode = call.argument<string>('mode') || 'rule';
    this.currentProxyMode = mode;
    hilog.info(DOMAIN, TAG, 'Proxy mode set to: %{public}s', mode);
    result.success(true);
  }

  private getDeviceInfo(result: MethodResult): void {
    try {
      const info: Record<string, string> = {
        brand: deviceInfo.brand,
        manufacturer: deviceInfo.manufacture,
        model: deviceInfo.productModel,
        device: deviceInfo.deviceType,
        display: deviceInfo.displayVersion,
        osFullName: deviceInfo.osFullName,
        sdkApiVersion: deviceInfo.sdkApiVersion.toString()
      };
      
      hilog.info(DOMAIN, TAG, 'Device info: %{public}s', JSON.stringify(info));
      result.success(info);
    } catch (error) {
      hilog.error(DOMAIN, TAG, 'Failed to get device info: %{public}s', JSON.stringify(error));
      result.error('DEVICE_INFO_ERROR', 'Failed to get device info', error);
    }
  }

  // Called from VPN extension when VPN starts
  notifyVpnStarted(fd: number): void {
    this.isVpnRunning = true;
    this.channel?.invokeMethod('onVpnStarted', {
      fd: fd,
      mode: this.currentProxyMode
    });
  }

  // Called from VPN extension when VPN stops
  notifyVpnStopped(): void {
    this.isVpnRunning = false;
    this.channel?.invokeMethod('onVpnStopped', null);
  }
}
