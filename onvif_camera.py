import sys
import json
import os
import time
import logging
from datetime import datetime, timezone
from onvif import ONVIFCamera
import zeep
from urllib.parse import urlparse, urlunparse
import requests
import threading
import argparse
from types import SimpleNamespace

class SOAPDebugHandler(logging.Handler):
    """Custom handler for XML message logging"""
    def __init__(self, filename):
        super().__init__()
        self.filename = filename
        self.setFormatter(logging.Formatter('%(message)s'))

    def emit(self, record):
        with open(self.filename, 'a') as f:
            f.write(self.format(record) + '\n\n')

class SOAPFilter(logging.Filter):
    """Filter for formatting SOAP messages"""
    def filter(self, record):
        if record.msg.startswith("HTTP Post to"):
            record.msg = "\n" + "="*80 + "\nSOAP REQUEST:\n" + record.msg
        elif record.msg.startswith("HTTP Response from"):
            record.msg = "\n" + "="*80 + "\nSOAP RESPONSE:\n" + record.msg
        return True

def setup_logging(debug=False):
    """Configure logging based on debug mode"""
    logger = logging.getLogger("CameraScanner")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    if debug:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.INFO)
        logger.addHandler(console_handler)
        
        # File handler
        log_file = f"camera_scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)

        # SOAP loggers
        for name in ['zeep', 'zeep.transports']:
            soap_logger = logging.getLogger(name)
            soap_logger.setLevel(logging.DEBUG)
            soap_logger.propagate = False
            soap_file = f"soap_messages_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            soap_handler = SOAPDebugHandler(soap_file)
            soap_handler.addFilter(SOAPFilter())
            soap_logger.addHandler(soap_handler)
    else:
        # Error-only logging in non-debug mode
        error_log_file = "camera_scanner_errors.log"
        error_handler = logging.FileHandler(error_log_file)
        error_handler.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        error_handler.setFormatter(formatter)
        logger.addHandler(error_handler)

    return logger

class ONVIFScanner:
    def __init__(self, wsdl_path='/usr/local/share/onvif/wsdl', logger=None):
        self.wsdl_path = wsdl_path
        os.makedirs(self.wsdl_path, exist_ok=True)
        self.logger = logger or logging.getLogger("CameraScanner")
        self.event_subscriptions = {}

    def create_onvif_client(self, ip, port, username, password, auth_type='digest'):
        """Create ONVIF client with proper authentication"""
        try:
            session = requests.Session()
            session.verify = False
            session.timeout = 10

            if auth_type == 'digest':
                from requests.auth import HTTPDigestAuth
                session.auth = HTTPDigestAuth(username, password)
            elif auth_type == 'basic':
                from requests.auth import HTTPBasicAuth
                session.auth = HTTPBasicAuth(username, password)

            transport = zeep.Transport(
                session=session,
                timeout=10,
                operation_timeout=10
            )

            cam = ONVIFCamera(
                ip,
                port,
                username,
                password,
                self.wsdl_path,
                transport=transport
            )

            cam.update_xaddrs()
            cam.create_devicemgmt_service()
            cam.create_media_service()

            cam.scanner_username = username
            cam.scanner_password = password
            cam.scanner_ip = ip
            cam.scanner_port = port

            return cam
        except Exception as e:
            self.logger.error(f"Error creating ONVIF client: {str(e)}", exc_info=True)
            return None

    def get_device_info(self, cam):
        """Get device information"""
        try:
            if not hasattr(cam, 'devicemgmt'):
                return {}

            info = cam.devicemgmt.GetDeviceInformation()

            return {
                "manufacturer": getattr(info, 'Manufacturer', "N/A"),
                "model": getattr(info, 'Model', "N/A"),
                "firmware": getattr(info, 'FirmwareVersion', "N/A"),
                "serial": getattr(info, 'SerialNumber', "N/A"),
                "hardware": getattr(info, 'HardwareId', "N/A")
            }
        except Exception as e:
            self.logger.error(f"Error getting device info: {str(e)}", exc_info=True)
            return {}

    def get_profiles(self, cam):
        """Get all camera profiles"""
        try:
            if not hasattr(cam, 'media'):
                return []

            profiles = cam.media.GetProfiles()
            profiles_info = []
            
            for profile in profiles:
                try:
                    profile_info = {
                        "token": getattr(profile, 'token', "unknown"),
                        "name": getattr(profile, 'Name', "Unnamed"),
                    }

                    # Video information
                    if hasattr(profile, 'VideoEncoderConfiguration'):
                        video = profile.VideoEncoderConfiguration
                        resolution = getattr(video, 'Resolution', None)
                        rate_control = getattr(video, 'RateControl', None)
                        
                        profile_info["video"] = {
                            "encoding": getattr(video, 'Encoding', "N/A"),
                            "resolution": {
                                "width": getattr(resolution, 'Width', 0),
                                "height": getattr(resolution, 'Height', 0)
                            } if resolution else {"width": 0, "height": 0},
                            "quality": getattr(video, 'Quality', "N/A"),
                            "fps": getattr(rate_control, 'FrameRateLimit', "N/A") if rate_control else "N/A",
                            "bitrate": getattr(rate_control, 'BitrateLimit', "N/A") if rate_control else "N/A"
                        }

                    # Audio information
                    if hasattr(profile, 'AudioEncoderConfiguration'):
                        audio = profile.AudioEncoderConfiguration
                        profile_info["audio"] = {
                            "encoding": getattr(audio, 'Encoding', "N/A"),
                            "bitrate": getattr(audio, 'Bitrate', "N/A"),
                            "samplerate": getattr(audio, 'SampleRate', "N/A")
                        }

                    profiles_info.append(profile_info)
                except Exception as e:
                    self.logger.warning(f"Error processing profile: {str(e)}", exc_info=True)
            return profiles_info
        except Exception as e:
            self.logger.error(f"Error getting profiles: {str(e)}", exc_info=True)
            return []

    def get_stream_uri(self, cam, profile_token):
        """Get stream URI for specific profile"""
        try:
            if not hasattr(cam, 'media'):
                return ""

            stream_uri = cam.media.GetStreamUri({
                'StreamSetup': {
                    'Stream': 'RTP-Unicast',
                    'Transport': {'Protocol': 'RTSP'}
                },
                'ProfileToken': profile_token
            })

            return getattr(stream_uri, 'Uri', "") if stream_uri else ""
        except Exception as e:
            self.logger.error(f"Error getting stream URI: {str(e)}", exc_info=True)
            return ""

    def get_rtsp_urls(self, cam, profiles):
        """Get RTSP URLs for all profiles"""
        rtsp_urls = {}
        for profile in profiles:
            try:
                token = profile.get("token", "")
                if not token:
                    continue

                uri = self.get_stream_uri(cam, token)
                if not uri:
                    continue

                # Parse and rebuild URI with credentials
                parsed = urlparse(uri)
                netloc = f"{cam.scanner_ip}:{parsed.port}" if parsed.port else cam.scanner_ip
                if hasattr(cam, 'scanner_username') and hasattr(cam, 'scanner_password'):
                    netloc = f"{cam.scanner_username}:{cam.scanner_password}@{netloc}"

                rtsp_url = urlunparse((
                    parsed.scheme,
                    netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))

                rtsp_urls[token] = rtsp_url
            except Exception:
                pass
        return rtsp_urls

    def get_network_settings(self, cam):
        """Get camera network settings"""
        try:
            if not hasattr(cam, 'devicemgmt'):
                return {}

            interfaces = cam.devicemgmt.GetNetworkInterfaces()
            if not interfaces:
                return {}
                
            # Take first interface
            interface = interfaces[0]
            info = {
                "mac": getattr(
                    getattr(interface, 'Info', None),
                    'HwAddress', "N/A"
                ) if hasattr(interface, 'Info') else "N/A"
            }

            # IPv4 settings
            if hasattr(interface, 'IPv4'):
                ipv4 = interface.IPv4
                info["ipv4"] = {
                    "enabled": getattr(ipv4, 'Enabled', False),
                    "dhcp": getattr(
                        getattr(ipv4, 'Config', None),
                        'DHCP', False
                    ) if hasattr(ipv4, 'Config') else False,
                }

                # Get IP address and netmask
                if hasattr(ipv4, 'Config') and hasattr(ipv4.Config, 'Manual'):
                    for addr in ipv4.Config.Manual:
                        if hasattr(addr, 'Address') and hasattr(addr, 'PrefixLength'):
                            info["ipv4"]["address"] = addr.Address
                            info["ipv4"]["netmask"] = addr.PrefixLength
                            break

            return info
        except Exception as e:
            self.logger.error(f"Error getting network settings: {str(e)}", exc_info=True)
            return {}

    def get_system_date(self, cam):
        """Get camera system date/time"""
        try:
            if not hasattr(cam, 'devicemgmt'):
                return {}

            system_date = cam.devicemgmt.GetSystemDateAndTime()
            if not system_date:
                return {}
                
            # UTC time
            utc = getattr(system_date, 'UTCDateTime', {})
            time_info = getattr(utc, 'Time', {})
            date_info = getattr(utc, 'Date', {})
            
            return {
                "utc": {
                    "time": f"{getattr(time_info, 'Hour', 0)}:{getattr(time_info, 'Minute', 0)}:{getattr(time_info, 'Second', 0)}",
                    "date": f"{getattr(date_info, 'Year', 0)}-{getattr(date_info, 'Month', 0)}-{getattr(date_info, 'Day', 0)}"
                },
                "timezone": getattr(
                    getattr(system_date, 'TimeZone', None),
                    'TZ', "N/A"
                ) if hasattr(system_date, 'TimeZone') else "N/A"
            }
        except Exception as e:
            self.logger.error(f"Error getting system date: {str(e)}", exc_info=True)
            return {}

    def get_capabilities(self, cam):
        """Get device capabilities"""
        try:
            if not hasattr(cam, 'devicemgmt'):
                return {}

            caps = cam.devicemgmt.GetCapabilities()
            if not caps:
                return {}
                
            return {
                "analytics": getattr(getattr(caps, 'Analytics', None), 'XAddr', "") if hasattr(caps, 'Analytics') else "",
                "device": getattr(getattr(caps, 'Device', None), 'XAddr', "") if hasattr(caps, 'Device') else "",
                "events": getattr(getattr(caps, 'Events', None), 'XAddr', "") if hasattr(caps, 'Events') else "",
                "imaging": getattr(getattr(caps, 'Imaging', None), 'XAddr', "") if hasattr(caps, 'Imaging') else "",
                "media": getattr(getattr(caps, 'Media', None), 'XAddr', "") if hasattr(caps, 'Media') else "",
                "ptz": getattr(getattr(caps, 'PTZ', None), 'XAddr', "") if hasattr(caps, 'PTZ') else ""
            }
        except Exception as e:
            self.logger.error(f"Error getting capabilities: {str(e)}", exc_info=True)
            return {}

    def get_ptz_service(self, cam):
        """Get PTZ service"""
        try:
            if not hasattr(cam, 'ptz'):
                cam.create_ptz_service()
            return cam.ptz if hasattr(cam, 'ptz') else None
        except Exception:
            return None

    def get_ptz_info(self, cam):
        """Get PTZ information"""
        try:
            ptz_service = self.get_ptz_service(cam)
            if not ptz_service:
                return {"supported": False}
                
            configs = ptz_service.GetConfigurations() or []
            nodes = ptz_service.GetNodes() or []
            
            return {
                "supported": True,
                "configurations": [
                    {
                        "name": getattr(c, 'Name', ""),
                        "token": getattr(c, 'token', "")
                    } for c in configs
                ],
                "nodes": [
                    {
                        "name": getattr(n, 'Name', ""),
                        "presets": getattr(n, 'MaximumNumberOfPresets', 0),
                        "home": getattr(n, 'HomeSupported', False)
                    } for n in nodes
                ]
            }
        except Exception:
            return {"supported": False}

    def scan_camera(self, ip, port, username, password, auth_type='digest'):
        """Scan camera and return structured data"""
        result = {
            "ip": ip,
            "port": port,
            "username": username,
            "auth_type": auth_type,
            "success": False,
            "device": {},
            "streams": [],
            "network": {},
            "system": {},
            "capabilities": {},
            "ptz": {},
            "camera_id": ""
        }

        try:
            cam = self.create_onvif_client(ip, port, username, password, auth_type)
            if not cam:
                result["error"] = "Failed to connect to camera"
                return result

            # Get device info
            device_info = self.get_device_info(cam)
            result["device"] = device_info
            
            # Generate camera ID
            manufacturer = device_info.get("manufacturer", "Unknown").replace(" ", "_")
            model = device_info.get("model", "Unknown").replace(" ", "_")
            result["camera_id"] = f"{manufacturer}_{model}_{ip.replace('.', '-')}_{port}"

            # Get capabilities
            result["capabilities"] = self.get_capabilities(cam)
            
            # Get profiles and streams
            profiles = self.get_profiles(cam)
            rtsp_urls = self.get_rtsp_urls(cam, profiles)
            
            for profile in profiles:
                token = profile.get("token", "")
                if token in rtsp_urls:
                    video = profile.get("video", {})
                    resolution = video.get("resolution", {})
                    result["streams"].append({
                        "profile": profile.get("name", "Unnamed"),
                        "encoding": video.get("encoding", "N/A"),
                        "resolution": f"{resolution.get('width', 0)}x{resolution.get('height', 0)}",
                        "fps": video.get("fps", "N/A"),
                        "bitrate": video.get("bitrate", "N/A"),
                        "url": rtsp_urls[token]
                    })

            # Get network settings
            result["network"] = self.get_network_settings(cam)
            
            # Get system time
            result["system"] = self.get_system_date(cam)
            
            # Get PTZ info
            result["ptz"] = self.get_ptz_info(cam)
            
            result["success"] = True

        except Exception as e:
            result["error"] = str(e)

        return result

    def sync_date(self, ip, port, username, password, auth_type='digest'):
        """Sync camera date/time with server time"""
        result = {
            "ip": ip,
            "port": port,
            "username": username,
            "auth_type": auth_type,
            "success": False
        }

        try:
            cam = self.create_onvif_client(ip, port, username, password, auth_type)
            if not cam or not hasattr(cam, 'devicemgmt'):
                result["error"] = "Failed to connect to camera"
                return result

            now = datetime.now(timezone.utc)
            cam.devicemgmt.SetSystemDateAndTime({
                'DateTimeType': 'Manual',
                'DaylightSavings': False,
                'TimeZone': {'TZ': 'GMT+00:00'},
                'UTCDateTime': {
                    'Date': {'Year': now.year, 'Month': now.month, 'Day': now.day},
                    'Time': {'Hour': now.hour, 'Minute': now.minute, 'Second': now.second}
                }
            })

            result["success"] = True
            result["message"] = "Time synchronized successfully"
            return result
        except Exception as e:
            result["error"] = str(e)
            return result

    def reboot_camera(self, ip, port, username, password, auth_type='digest'):
        """Reboot camera"""
        result = {
            "ip": ip,
            "port": port,
            "username": username,
            "auth_type": auth_type,
            "success": False
        }

        try:
            cam = self.create_onvif_client(ip, port, username, password, auth_type)
            if not cam or not hasattr(cam, 'devicemgmt'):
                result["error"] = "Failed to connect to camera"
                return result

            cam.devicemgmt.SystemReboot()
            result["success"] = True
            result["message"] = "Reboot command sent"
            return result
        except Exception as e:
            result["error"] = str(e)
            return result

    def ptz_continuous_move(self, cam, profile_token, pan=0, tilt=0, zoom=0, timeout=5):
        """Continuous PTZ movement"""
        result = {
            "command": "ptz_move",
            "profile_token": profile_token,
            "success": False
        }

        try:
            ptz_service = self.get_ptz_service(cam)
            if not ptz_service:
                result["error"] = "PTZ service not available"
                return result

            ptz_service.ContinuousMove({
                'ProfileToken': profile_token,
                'Velocity': {
                    'PanTilt': {'x': pan, 'y': tilt},
                    'Zoom': {'x': zoom}
                },
                'Timeout': timeout
            })

            result["success"] = True
            return result
        except Exception as e:
            result["error"] = str(e)
            return result

    def ptz_stop(self, cam, profile_token):
        """Stop PTZ movement"""
        result = {
            "command": "ptz_stop",
            "profile_token": profile_token,
            "success": False
        }

        try:
            ptz_service = self.get_ptz_service(cam)
            if not ptz_service:
                result["error"] = "PTZ service not available"
                return result

            ptz_service.Stop({
                'ProfileToken': profile_token,
                'PanTilt': True,
                'Zoom': True
            })

            result["success"] = True
            return result
        except Exception as e:
            result["error"] = str(e)
            return result

    def ptz_absolute_move(self, cam, profile_token, pan=0, tilt=0, zoom=0):
        """Absolute PTZ movement"""
        result = {
            "command": "ptz_abs_move",
            "profile_token": profile_token,
            "success": False
        }

        try:
            ptz_service = self.get_ptz_service(cam)
            if not ptz_service:
                result["error"] = "PTZ service not available"
                return result

            ptz_service.AbsoluteMove({
                'ProfileToken': profile_token,
                'Position': {
                    'PanTilt': {'x': pan, 'y': tilt},
                    'Zoom': {'x': zoom}
                }
            })

            result["success"] = True
            return result
        except Exception as e:
            result["error"] = str(e)
            return result

    def get_events_service(self, cam):
        """Get events service"""
        try:
            if not hasattr(cam, 'events'):
                cam.create_events_service()
            return cam.events if hasattr(cam, 'events') else None
        except Exception:
            return None

    def create_event_subscription(self, cam, callback):
        """Create event subscription"""
        try:
            events_service = self.get_events_service(cam)
            if not events_service:
                return None

            subscription = events_service.CreatePullPointSubscription()
            if not subscription or not hasattr(subscription, 'SubscriptionReference'):
                return None

            sub_ref = subscription.SubscriptionReference.Address
            self.event_subscriptions[sub_ref] = {
                'cam': cam,
                'callback': callback,
                'running': True
            }

            thread = threading.Thread(target=self.event_listener, args=(sub_ref,))
            thread.daemon = True
            thread.start()
            return sub_ref
        except Exception:
            return None

    def event_listener(self, sub_ref):
        """Listen for events"""
        if sub_ref not in self.event_subscriptions:
            return

        sub_info = self.event_subscriptions[sub_ref]
        events_service = self.get_events_service(sub_info['cam'])

        if not events_service:
            return

        try:
            while sub_info['running']:
                events = events_service.PullMessages({
                    'Timeout': 'PT1S',
                    'MessageLimit': 10
                }) or []

                for msg in getattr(events, 'NotificationMessage', []):
                    topic = getattr(getattr(msg, 'Topic', None), '_value_1', "")
                    if 'RuleEngine/MotionRegionDetector/Motion' in topic:
                        state = getattr(getattr(msg, 'Message', None), '_value_1', {})
                        if 'State' in state:
                            event_data = {
                                'event_type': 'motion',
                                'state': state['State'] == 'true',
                                'source': state.get('Source', {}).get('SimpleItem', {}).get('Value', 'Unknown'),
                                'timestamp': datetime.now().isoformat()
                            }
                            sub_info['callback'](event_data)
                time.sleep(0.1)
        except Exception:
            pass

    def stop_event_subscription(self, sub_ref):
        """Stop event subscription"""
        if sub_ref in self.event_subscriptions:
            self.event_subscriptions[sub_ref]['running'] = False
            del self.event_subscriptions[sub_ref]
            return True
        return False

def clean_json_serializer(obj):
    """Clean JSON serializer for ONVIF objects"""
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    if isinstance(obj, (list, tuple)):
        return [clean_json_serializer(x) for x in obj]
    if isinstance(obj, dict):
        return {k: clean_json_serializer(v) for k, v in obj.items()}
    if hasattr(obj, '__dict__'):
        return clean_json_serializer({k: v for k, v in obj.__dict__.items() 
                                     if not k.startswith('_')})
    return str(obj)

def print_json(data):
    """Print data as formatted JSON"""
    print(json.dumps(
        data,
        indent=2,
        ensure_ascii=False,
        default=clean_json_serializer
    ))

def main():
    parser = argparse.ArgumentParser(description='ONVIF Camera Management Tool')
    parser.add_argument('--wsdl-path', default='/usr/local/share/onvif/wsdl',
                        help='Path to WSDL directory')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Common parameters
    base_parser = argparse.ArgumentParser(add_help=False)
    base_parser.add_argument('ip', help='Camera IP address')
    base_parser.add_argument('-p', '--port', type=int, default=80, help='Camera port')
    base_parser.add_argument('-u', '--username', default='admin', help='Username')
    base_parser.add_argument('-P', '--password', default='', help='Password')
    base_parser.add_argument('-a', '--auth-type', choices=['digest', 'basic'], default='digest',
                            help='Authentication type')

    # Scan command
    scan_parser = subparsers.add_parser('scan', parents=[base_parser], help='Scan camera')

    # Sync date command
    sync_parser = subparsers.add_parser('sync_date', parents=[base_parser], help='Sync camera date/time')

    # Reboot command
    reboot_parser = subparsers.add_parser('reboot', parents=[base_parser], help='Reboot camera')

    # PTZ commands
    ptz_parser = argparse.ArgumentParser(add_help=False)
    ptz_parser.add_argument('profile_token', help='PTZ profile token')

    ptz_move_parser = subparsers.add_parser('ptz_move', parents=[base_parser, ptz_parser],
                                           help='Continuous PTZ movement')
    ptz_move_parser.add_argument('pan', type=float, help='Pan value (-1.0 to 1.0)')
    ptz_move_parser.add_argument('tilt', type=float, help='Tilt value (-1.0 to 1.0)')
    ptz_move_parser.add_argument('zoom', type=float, help='Zoom value (-1.0 to 1.0)')
    ptz_move_parser.add_argument('-t', '--timeout', type=float, default=5.0,
                                help='Movement timeout in seconds')

    ptz_stop_parser = subparsers.add_parser('ptz_stop', parents=[base_parser, ptz_parser],
                                           help='Stop PTZ movement')

    ptz_abs_parser = subparsers.add_parser('ptz_abs_move', parents=[base_parser, ptz_parser],
                                          help='Absolute PTZ movement')
    ptz_abs_parser.add_argument('pan', type=float, help='Pan value')
    ptz_abs_parser.add_argument('tilt', type=float, help='Tilt value')
    ptz_abs_parser.add_argument('zoom', type=float, help='Zoom value')

    # Events command
    events_parser = subparsers.add_parser('events', parents=[base_parser],
                                         help='Monitor motion events')

    args = parser.parse_args()
    logger = setup_logging(debug=args.debug)
    scanner = ONVIFScanner(wsdl_path=args.wsdl_path, logger=logger)

    if args.command == 'scan':
        result = scanner.scan_camera(
            args.ip, args.port, args.username, args.password, args.auth_type
        )
        print_json(result)

    elif args.command == 'sync_date':
        result = scanner.sync_date(
            args.ip, args.port, args.username, args.password, args.auth_type
        )
        print_json(result)

    elif args.command == 'reboot':
        result = scanner.reboot_camera(
            args.ip, args.port, args.username, args.password, args.auth_type
        )
        print_json(result)

    elif args.command == 'ptz_move':
        cam = scanner.create_onvif_client(
            args.ip, args.port, args.username, args.password, args.auth_type
        )
        if cam:
            result = scanner.ptz_continuous_move(
                cam, args.profile_token, args.pan, args.tilt, args.zoom, args.timeout
            )
            print_json(result)
        else:
            print_json({"error": "Failed to connect to camera"})

    elif args.command == 'ptz_stop':
        cam = scanner.create_onvif_client(
            args.ip, args.port, args.username, args.password, args.auth_type
        )
        if cam:
            result = scanner.ptz_stop(cam, args.profile_token)
            print_json(result)
        else:
            print_json({"error": "Failed to connect to camera"})

    elif args.command == 'ptz_abs_move':
        cam = scanner.create_onvif_client(
            args.ip, args.port, args.username, args.password, args.auth_type
        )
        if cam:
            result = scanner.ptz_absolute_move(
                cam, args.profile_token, args.pan, args.tilt, args.zoom
            )
            print_json(result)
        else:
            print_json({"error": "Failed to connect to camera"})

    elif args.command == 'events':
        def event_callback(event):
            print_json(event)

        cam = scanner.create_onvif_client(
            args.ip, args.port, args.username, args.password, args.auth_type
        )
        if cam:
            print(f"Monitoring motion events for {args.ip}:{args.port}")
            print("Press Ctrl+C to stop")
            sub_ref = scanner.create_event_subscription(cam, event_callback)
            if sub_ref:
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    scanner.stop_event_subscription(sub_ref)
                    print("Event monitoring stopped")
            else:
                print_json({"error": "Failed to create event subscription"})
        else:
            print_json({"error": "Failed to connect to camera"})

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
