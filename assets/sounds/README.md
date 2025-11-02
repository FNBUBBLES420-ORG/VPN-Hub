# VPN Hub Audio Assets

This directory contains audio files for notifications and alerts.

## Sound Categories

### Notifications (`notifications/`)
- **connection_success.wav**: Played when VPN connects successfully
- **connection_failed.wav**: Played when VPN connection fails
- **disconnected.wav**: Played when VPN disconnects
- **provider_switched.wav**: Played when switching VPN providers
- **server_changed.wav**: Played when changing VPN servers

### Security Alerts (`alerts/`)
- **security_threat.wav**: Critical security threat detected
- **authentication_failed.wav**: Authentication failure alert
- **privilege_escalation.wav**: Privilege escalation prompt
- **anomaly_detected.wav**: Suspicious activity detected
- **file_integrity_violation.wav**: File tampering detected

## Audio Specifications

### Format Requirements
- **Format**: WAV or MP3
- **Sample Rate**: 44.1 kHz
- **Bit Depth**: 16-bit
- **Channels**: Mono or Stereo
- **Duration**: 0.5-2 seconds for notifications, 2-5 seconds for alerts
- **File Size**: <100KB per file for quick loading

### Volume Guidelines
- **Notifications**: Moderate volume, not intrusive
- **Security Alerts**: Higher volume to ensure attention
- **All sounds**: Normalized to prevent volume spikes
- **Accessibility**: Support for system volume controls

## Usage Configuration

```json
{
  "audio_settings": {
    "notifications_enabled": true,
    "security_alerts_enabled": true,
    "volume_level": 0.7,
    "respect_system_mute": true,
    "custom_sounds": false
  }
}
```

## Accessibility Considerations

- All audio cues have visual equivalents
- Sounds can be disabled for hearing-impaired users
- Volume respects system accessibility settings
- Clear, distinct tones for different event types

## Security Notes

All audio files should be:
- ✅ Scanned for embedded malware
- ✅ Validated for proper audio format
- ✅ Optimized for size and quality
- ✅ Licensed appropriately for distribution