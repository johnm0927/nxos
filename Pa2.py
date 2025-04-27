import requests
import getpass
import ipaddress
from collections import defaultdict

# ==================== API Client & Config Collection ====================
class PaloAltoAPIClient:
    def __init__(self, host, username=None, password=None, api_key=None, verify_ssl=False):
        self.base_url = f"https://{host}/restapi/v10.2"
        self.verify_ssl = verify_ssl
        self.api_key = api_key or self._authenticate(username, password)
        self.headers = {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"}

    def _authenticate(self, username, password):
        if not username: username = input("Username: ")
        if not password: password = getpass.getpass("Password: ")
        try:
            response = requests.post(
                f"{self.base_url}/oauth2/request_token",
                data={"client_id": username, "client_secret": password, "grant_type": "password"},
                verify=self.verify_ssl
            )
            response.raise_for_status()
            return response.json()['access_token']
        except Exception as e:
            raise ConnectionError(f"Authentication failed: {str(e)}")

    def _paginated_get(self, endpoint, params=None):
        results = []
        offset = 0
        while True:
            response = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                params={'offset': offset, 'limit': 100, **(params or {})},
                verify=self.verify_ssl
            )
            response.raise_for_status()
            data = response.json()
            if 'result' not in data or 'entry' not in data['result']: break
            results.extend(data['result']['entry'])
            if len(data['result']['entry']) < 100: break
            offset += 100
        return results

class PaloAltoConfigCollector(PaloAltoAPIClient):
    def __init__(self, host, vsys='vsys1', **kwargs):
        super().__init__(host, **kwargs)
        self.vsys = vsys

    def get_full_config(self):
        return {
            "interfaces": self._paginated_get("/network/interfaces"),
            "static_routes": self._paginated_get("/network/virtual-routers/entry[@name='default']/routing-table/ip/static-route"),
            "zones": self._paginated_get("/objects/zones"),
            "address_objects": self._paginated_get("/objects/addresses", {'vsys': self.vsys, 'location': 'vsys'}),
            "address_groups": self._paginated_get("/objects/address-groups", {'vsys': self.vsys, 'location': 'vsys'}),
            "service_objects": self._paginated_get("/objects/services", {'vsys': self.vsys, 'location': 'vsys'}),
            "service_groups": self._paginated_get("/objects/service-groups", {'vsys': self.vsys, 'location': 'vsys'}),
            "applications": self._paginated_get("/objects/applications", {'vsys': self.vsys, 'location': 'vsys'}),
            "security_rules": self._paginated_get("/policies/security-rules", {'vsys': self.vsys, 'location': 'vsys'})
        }

# ==================== Configuration Parsing ====================
class PaloAltoConfigParser:
    def __init__(self, config_data):
        self.config = config_data
        self._parse_all()

    def _parse_all(self):
        # Network Components
        self._parse_interfaces()
        self._parse_static_routes()
        self._parse_zones()
        
        # Object Resolution
        self._parse_address_objects()
        self._parse_address_groups()
        self._parse_service_objects()
        self._parse_service_groups()
        self._parse_applications()
        
        # Security Policy
        self._parse_security_rules()

    def _parse_interfaces(self):
        self.interfaces = []
        for intf in self.config['interfaces']:
            ip_entry = intf.get('ip', {}).get('entry', [{}])[0]
            self.interfaces.append({
                'name': intf['@name'],
                'zone': intf.get('zone', ''),
                'ip': ip_entry.get('ip', ''),
                'mask': ip_entry.get('mask', '')
            })

    def _parse_static_routes(self):
        self.static_routes = []
        for route in self.config['static_routes']:
            self.static_routes.append({
                'destination': route['destination'],
                'interface': route.get('interface', ''),
                'nexthop': route.get('nexthop', {}).get('ip-address', '')
            })

    def _parse_zones(self):
        self.zone_interfaces = defaultdict(list)
        for zone in self.config['zones']:
            self.zone_interfaces[zone['@name']] = zone.get('network', {}).get('layer3', {}).get('member', [])

    def _parse_address_objects(self):
        self.address_objects = {}
        for addr in self.config['address_objects']:
            self.address_objects[addr['@name']] = addr.get('ip-netmask') or addr.get('fqdn')

    def _parse_address_groups(self):
        self.address_groups = defaultdict(list)
        for group in self.config['address_groups']:
            self.address_groups[group['@name']] = group.get('static', {}).get('member', [])

    def _parse_service_objects(self):
        self.service_objects = {}
        for svc in self.config['service_objects']:
            proto = next((p for p in ['tcp', 'udp'] if p in svc), 'any')
            self.service_objects[svc['@name']] = {
                'protocol': proto,
                'port': svc.get(proto, {}).get('port', 'any')
            }

    def _parse_service_groups(self):
        self.service_groups = defaultdict(list)
        for group in self.config['service_groups']:
            self.service_groups[group['@name']] = group.get('members', {}).get('member', [])

    def _parse_applications(self):
        self.applications = {}
        for app in self.config['applications']:
            app_info = {
                'protocol': 'icmp' if 'icmp' in app else 'any',
                'category': app.get('category', ''),
                'subcategory': app.get('subcategory', ''),
                'risk': app.get('risk', 1)
            }
            if 'icmp' in app:
                app_info.update({
                    'icmp_type': app['icmp'].get('type'),
                    'icmp_code': app['icmp'].get('code')
                })
            self.applications[app['@name']] = app_info

    def _parse_security_rules(self):
        self.security_rules = []
        for rule in self.config['security_rules']:
            self.security_rules.append({
                'name': rule['@name'],
                'disabled': rule.get('disabled', 'no') == 'yes',
                'from_zones': rule.get('from', {}).get('member', []),
                'to_zones': rule.get('to', {}).get('member', []),
                'sources': rule.get('source', {}).get('member', []),
                'destinations': rule.get('destination', {}).get('member', []),
                'services': rule.get('service', {}).get('member', []),
                'applications': rule.get('application', {}).get('member', []),
                'action': rule.get('action', 'deny')
            })

    # Resolution methods
    def resolve_address(self, address_name):
        if address_name in self.address_objects:
            return [self.address_objects[address_name]]
        if address_name in self.address_groups:
            return [ip for member in self.address_groups[address_name] for ip in self.resolve_address(member)]
        if address_name == 'any':
            return ['0.0.0.0/0']
        return []

    def resolve_service(self, service_name):
        if service_name in self.service_objects:
            return [self.service_objects[service_name]]
        if service_name in self.service_groups:
            return [srv for member in self.service_groups[service_name] for srv in self.resolve_service(member)]
        if service_name == 'any':
            return [{'protocol': 'any', 'port': 'any'}]
        return []

# ==================== Traffic Analysis ====================
class TrafficAnalyzer:
    def __init__(self, parser):
        self.parser = parser
        self.interface_networks = [
            (ipaddress.ip_network(f"{intf['ip']}/{intf['mask']}", strict=False), intf['zone'])
            for intf in parser.interfaces if intf['ip'] and intf['mask']
        ]
        self.static_routes = sorted(
            [r for r in parser.static_routes if '/' in r['destination']],
            key=lambda x: ipaddress.ip_network(x['destination']).prefixlen,
            reverse=True
        )

    def analyze_traffic(self, src_ip, dst_ip, protocol, port=None, icmp_type=None, icmp_code=None):
        src_zone = self._find_source_zone(src_ip)
        dst_zone = self._find_destination_zone(dst_ip)
        
        for rule in self.parser.security_rules:
            if rule['disabled']:
                continue
                
            if not (self._match_zones(src_zone, rule['from_zones'], dst_zone, rule['to_zones']):
                continue
                
            if not (self._match_address(src_ip, rule['sources']) and self._match_address(dst_ip, rule['destinations'])):
                continue
                
            service_match = any(
                self._match_service(svc, protocol, port)
                for svc in rule['services']
            )
            
            app_match = any(
                self._match_application(app, protocol, icmp_type, icmp_code)
                for app in rule['applications']
            )
            
            if service_match or app_match:
                return rule
        return None

    def _find_source_zone(self, ip):
        try:
            ip_addr = ipaddress.ip_address(ip)
            for net, zone in self.interface_networks:
                if ip_addr in net:
                    return zone
        except ValueError:
            return 'untrust'

    def _find_destination_zone(self, ip):
        try:
            ip_addr = ipaddress.ip_address(ip)
            for route in self.static_routes:
                if ip_addr in ipaddress.ip_network(route['destination']):
                    for intf in self.parser.interfaces:
                        if intf['name'] == route['interface']:
                            return intf['zone']
        except ValueError:
            pass
        return 'untrust'

    def _match_zones(self, src_zone, rule_src_zones, dst_zone, rule_dst_zones):
        return (('any' in rule_src_zones or src_zone in rule_src_zones) and
                ('any' in rule_dst_zones or dst_zone in rule_dst_zones))

    def _match_address(self, ip, rule_addresses):
        for addr in rule_addresses:
            for cidr in self.parser.resolve_address(addr):
                if cidr == 'any':
                    return True
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                        return True
                except ValueError:
                    continue
        return False

    def _match_service(self, service_name, protocol, port):
        for service in self.parser.resolve_service(service_name):
            proto_match = service['protocol'] in [protocol, 'any']
            port_match = service['port'] in [str(port), 'any']
            if proto_match and port_match:
                return True
        return False

    def _match_application(self, app_name, protocol, icmp_type, icmp_code):
        if app_name == 'any':
            return protocol == 'any'
            
        app = self.parser.applications.get(app_name)
        if not app:
            return False
            
        if app['protocol'] not in [protocol, 'any']:
            return False
            
        if protocol == 'icmp' and app['protocol'] == 'icmp':
            if app['icmp_type'] and str(icmp_type) != app['icmp_type']:
                return False
            if app['icmp_code'] and str(icmp_code) != app['icmp_code']:
                return False
                
        return True

# ==================== Main Execution ====================
if __name__ == "__main__":
    # Initialize connection
    firewall_host = input("Enter firewall IP/hostname: ")
    collector = PaloAltoConfigCollector(
        host=firewall_host,
        vsys='vsys1',
        verify_ssl=False
    )
    
    # Retrieve and parse config
    config_data = collector.get_full_config()
    parser = PaloAltoConfigParser(config_data)
    analyzer = TrafficAnalyzer(parser)
    
    # Get traffic parameters
    print("\nEnter traffic parameters:")
    src_ip = input("Source IP: ").strip()
    dst_ip = input("Destination IP: ").strip()
    protocol = input("Protocol (tcp/udp/icmp): ").strip().lower()
    
    port = None
    icmp_type = None
    icmp_code = None
    
    if protocol in ['tcp', 'udp']:
        port = input("Port: ").strip()
    elif protocol == 'icmp':
        icmp_type = input("ICMP type (e.g., 8 for echo request): ").strip()
        icmp_code = input("ICMP code (optional): ").strip() or None
    
    # Analyze traffic
    result = analyzer.analyze_traffic(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        port=port,
        icmp_type=icmp_type,
        icmp_code=icmp_code
    )
    
    # Display results
    if result:
        print(f"\nTraffic allowed by rule: {result['name']}")
        print(f"Action: {result['action'].upper()}")
        print(f"From Zones: {', '.join(result['from_zones'])}")
        print(f"To Zones: {', '.join(result['to_zones'])}")
        if result['applications']:
            print(f"Matching Applications: {', '.join(result['applications'])}")
        if result['services']:
            print(f"Matching Services: {', '.join(result['services'])}")
    else:
        print("\nTraffic denied by firewall policy")
