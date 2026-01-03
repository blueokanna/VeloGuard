import { VpnExtensionAbility } from '@kit.NetworkKit';
import { Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';

const TAG = 'CatClashVpn';
const DOMAIN = 0x0000;

/**
 * CatClash VPN Extension for HarmonyOS NEXT
 * 
 * This extension handles VPN tunnel creation and management.
 * It works with the Flutter layer through method channels.
 */
export default class CatClashVpnExtension extends VpnExtensionAbility {
  private vpnConnection: VpnConnection | null = null;
  private isRunning: boolean = false;
  private proxyMode: string = 'rule';

  onCreate(): void {
    hilog.info(DOMAIN, TAG, 'VPN Extension onCreate');
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, 'VPN Extension onDestroy');
    this.stopVpn();
  }

  onRequest(want: Want, startId: number): void {
    hilog.info(DOMAIN, TAG, 'VPN Extension onRequest, startId: %{public}d', startId);
    
    const action = want.parameters?.action as string;
    const mode = want.parameters?.mode as string || 'rule';
    
    if (action === 'start') {
      this.proxyMode = mode;
      this.startVpn();
    } else if (action === 'stop') {
      this.stopVpn();
    }
  }

  private async startVpn(): Promise<void> {
    if (this.isRunning) {
      hilog.warn(DOMAIN, TAG, 'VPN already running, stopping first...');
      await this.stopVpn();
    }

    try {
      hilog.info(DOMAIN, TAG, 'Starting VPN with mode: %{public}s', this.proxyMode);
      
      // Create VPN configuration
      const vpnConfig: VpnConfig = {
        addresses: [{
          address: '198.18.0.1',
          prefixLength: 16
        }],
        routes: [{
          destination: '0.0.0.0',
          prefixLength: 0
        }],
        dnsAddresses: ['198.18.0.2', '8.8.8.8', '1.1.1.1'],
        mtu: 1500,
        isBlocking: false
      };

      // Establish VPN connection
      this.vpnConnection = await this.createVpnConnection(vpnConfig);
      
      if (this.vpnConnection) {
        this.isRunning = true;
        const fd = this.vpnConnection.fd;
        hilog.info(DOMAIN, TAG, 'VPN started successfully, fd: %{public}d', fd);
        
        // Notify Flutter layer
        this.notifyVpnStarted(fd);
      } else {
        hilog.error(DOMAIN, TAG, 'Failed to establish VPN connection');
      }
    } catch (error) {
      hilog.error(DOMAIN, TAG, 'Error starting VPN: %{public}s', JSON.stringify(error));
      this.isRunning = false;
    }
  }

  private async stopVpn(): Promise<void> {
    hilog.info(DOMAIN, TAG, 'Stopping VPN...');
    
    this.isRunning = false;
    
    if (this.vpnConnection) {
      try {
        await this.vpnConnection.destroy();
        this.vpnConnection = null;
        hilog.info(DOMAIN, TAG, 'VPN connection destroyed');
      } catch (error) {
        hilog.error(DOMAIN, TAG, 'Error destroying VPN connection: %{public}s', JSON.stringify(error));
      }
    }
    
    // Notify Flutter layer
    this.notifyVpnStopped();
  }

  private notifyVpnStarted(fd: number): void {
    // Send event to Flutter through common event mechanism
    // This will be handled by the Flutter method channel
    hilog.info(DOMAIN, TAG, 'Notifying VPN started with fd: %{public}d', fd);
  }

  private notifyVpnStopped(): void {
    hilog.info(DOMAIN, TAG, 'Notifying VPN stopped');
  }
}

// VPN Configuration interface
interface VpnConfig {
  addresses: Array<{
    address: string;
    prefixLength: number;
  }>;
  routes: Array<{
    destination: string;
    prefixLength: number;
  }>;
  dnsAddresses: string[];
  mtu: number;
  isBlocking: boolean;
}

// VPN Connection interface
interface VpnConnection {
  fd: number;
  destroy(): Promise<void>;
}
