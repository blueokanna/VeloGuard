package com.blueokanna.veloguard

import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi

@RequiresApi(Build.VERSION_CODES.N)
class VeloGuardTileService : TileService() {
    
    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }
    
    override fun onClick() {
        super.onClick()
        
        if (VeloGuardVpnService.isRunning) {
            val intent = Intent(this, VeloGuardVpnService::class.java).apply {
                action = VeloGuardVpnService.ACTION_STOP
            }
            startService(intent)
        } else {
            val intent = Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra("start_vpn", true)
            }
            startActivityAndCollapse(intent)
        }
        
        updateTile()
    }
    
    private fun updateTile() {
        val tile = qsTile ?: return
        
        if (VeloGuardVpnService.isRunning) {
            tile.state = Tile.STATE_ACTIVE
            tile.label = "VeloGuard"
            tile.contentDescription = "VPN 已连接"
        } else {
            tile.state = Tile.STATE_INACTIVE
            tile.label = "VeloGuard"
            tile.contentDescription = "VPN 已断开"
        }
        
        tile.updateTile()
    }
}
