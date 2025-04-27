import requests
import getpass
import json
import ipaddress
from collections import defaultdict

class PaloAltoAPIClient:
    """Handles authentication and API communication"""
    def __init__(self, host, username=None, password=None, api_key=None, verify_ssl=False):
        self.base_url = f"https://{host}/restapi/v10.2"
        self.verify_ssl = verify_ssl
        self.api_key = api_key or self._authenticate(username, password)
        
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json"
        }

    def _authenticate(self, username, password):
        """Automatically obtain API key using credentials"""
        if not username:
            username = input("Enter firewall username: ")
        if not password:
            password = getpass.getpass("Enter firewall password: ")

        auth_url = f"{self.base_url}/oauth2/request_token"
        try:
            response = requests.post(
                auth_url,
                data={
                    "client_id": username,
                    "client_secret": password,
                    "grant_type": "password"
                },
                verify=self.verify_ssl
            )
            response.raise_for_status()
            return response.json()['access_token']
        except requests.exceptions.HTTPError as e:
            raise Exception(f"Authentication failed: {e.response.text}")

    def _paginated_get(self, endpoint, params=None):
        """Handle paginated API responses"""
        results = []
        offset = 0
        while True:
            request_params = {'offset': offset, 'limit': 100, **(params or {})}
            response = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                params=request_params,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            data = response.json()
            
            if 'result' not in data or 'entry' not in data['result']:
                break
                
            results.extend(data['result']['entry'])
            if len(data['result']['entry']) < 100:
                break
            offset += 100
        return results

class PaloAltoConfigCollector(PaloAltoAPIClient):
    """Collects configuration data from Palo Alto firewall"""
    def __init__(self, host, vsys='vsys1', **kwargs):
        super().__init__(host, **kwargs)
        self.vsys = vsys

    def get_full_config(self):
        """Retrieve complete firewall configuration"""
        return {
            "interfaces": self.get_interfaces(),
            "static_routes": self.get_static_routes(),
            "zones": self.get_zones(),
            "address_objects": self.get_address_objects(),
            "service_objects": self.get_service_objects(),
            "security_rules": self.get_security_rules()
        }

    def get_interfaces(self):
        return self._paginated_get("/network/interfaces")

    def get_static_routes(self):
        return self._paginated_get(
            "/network/virtual-routers/entry[@name='default']/routing-table/ip/static-route"
        )

    def get_zones(self):
        return self._paginated_get("/objects/zones")

    def get_address_objects(self):
        return self._paginated_get(
            "/objects/addresses",
            params={'vsys': self.vsys, 'location': 'vsys'}
        )

    def get_service_objects(self):
        return self._paginated_get(
            "/objects/services",
            params={'vsys': self.vsys, 'location': 'vsys'}
        )

    def get_security_rules(self):
        return self._paginated_get(
            "/policies/security-rules",
            params={'vsys': self.vsys, 'location': 'vsys'}
        )

class PaloAltoConfigParser:
    """Parses and analyzes firewall configuration"""
    def __init__(self, config_data):
        self.config = config_data
        self.interfaces = []
        self.static_routes = []
        self.zones = defaultdict(list)
        self.address_objects = {}
        self.service_objects = {}
        self.security_rules = []
        
        self._parse_config()
        self._prepare_interface_mappings()

    def _parse_config(self):
        self._parse_interfaces()
        self._parse_static_routes()
        self._parse_zones()
        self._parse_address_objects()
        self._parse_service_objects()
        self._parse_security_rules()

    def _parse_interfaces(self):
        for interface in self.config['interfaces']:
            entry = {
                'name': interface['@name'],
                'zone': interface.get('zone', ''),
                'ip': interface.get('ip', {}).get('entry', [{}])[0].get('ip', ''),
                'subnet': interface.get('ip', {}).get('entry', [{}])[0].get('mask', '')
            }
            self.interfaces.append(entry)

    def _parse_static_routes(self):
        for route in self.config['static_routes']:
            self.static_routes.append({
                'destination': route['destination'],
                'interface': route.get('interface', ''),
                'nexthop': route.get('nexthop', {}).get('ip-address', '')
            })

    def _parse_zones(self):
        for zone in self.config['zones']:
            self.zones[zone['@name']] = zone.get('network', {}).get('layer3', {}).get('member', [])

    def _parse_address_objects(self):
        for addr in self.config['address_objects']:
            self.address_objects[addr['@name']] = {
                'type': 'ip-netmask',
                'value': addr.get('ip-netmask', '')
            }

    def _parse_service_objects(self):
        for service in self.config['service_objects']:
            proto = 'tcp' if 'tcp' in service else 'udp' if 'udp' in service else 'any'
            self.service_objects[service['@name']] = {
                'protocol': proto,
                'port': service.get(proto, {}).get('port', 'any')
            }

    def _parse_security_rules(self):
        for rule in self.config['security_rules']:
            self.security_rules.append({
                'name': rule['@name'],
                'from_zones': rule.get('from', {}).get('member', []),
                'to_zones': rule.get('to', {}).get('member', []),
                'sources': rule.get('source', {}).get('member', []),
                'destinations': rule.get('destination', {}).get('member', []),
                'services': rule.get('service', {}).get('member', []),
                'action': rule.get('action', 'deny')
            })

    def _prepare_interface_mappings(self):
        self.interface_subnets = []
        for interface in self.interfaces:
            if interface['ip'] and interface['subnet']:
                try:
                    network = ipaddress.ip_network(
                        f"{interface['ip']}/{interface['subnet']}", 
                        strict=False
                    )
                    self.interface_subnets.append({
                        'interface': interface['name'],
                        'zone': interface['zone'],
                        'network': network
                    })
                except ValueError:
                    continue

class TrafficAnalyzer:
    """Analyzes traffic against firewall rules"""
    def __init__(self, config_parser):
        self.parser = config_parser
        self.static_routes = sorted(
            config_parser.static_routes,
            key=lambda x: ipaddress.ip_network(x['destination']).prefixlen,
            reverse=True
        )

    def analyze_traffic(self, src_ip, dst_ip, protocol, port=None):
        src_zone = self._find_source_zone(src_ip)
        dst_zone = self._find_destination_zone(dst_ip)
        
        for rule in self.parser.security_rules:
            if self._rule_matches(rule, src_ip, src_zone, dst_ip, dst_zone, protocol, port):
                return rule
        return None

    def _find_source_zone(self, ip):
        try:
            ip_addr = ipaddress.ip_address(ip)
            for subnet in self.parser.interface_subnets:
                if ip_addr in subnet['network']:
                    return subnet['zone']
        except ValueError:
            return 'untrust'

    def _find_destination_zone(self, ip):
        try:
            ip_addr = ipaddress.ip_address(ip)
            for route in self.static_routes:
                net = ipaddress.ip_network(route['destination'])
                if ip_addr in net:
                    return self._interface_to_zone(route['interface'])
        except ValueError:
            return 'untrust'

    def _interface_to_zone(self, interface_name):
        for subnet in self.parser.interface_subnets:
            if subnet['interface'] == interface_name:
                return subnet['zone']
        return 'untrust'

    def _rule_matches(self, rule, src_ip, src_zone, dst_ip, dst_zone, protocol, port):
        # Check zone matching
        if not (self._zone_match(src_zone, rule['from_zones']) and 
                self._zone_match(dst_zone, rule['to_zones'])):
            return False
        
        # Check address matching
        if not (self._address_match(src_ip, rule['sources']) and 
                self._address_match(dst_ip, rule['destinations'])):
            return False
        
        # Check service matching
        return self._service_match(rule['services'], protocol, port)

    def _zone_match(self, traffic_zone, rule_zones):
        return 'any' in rule_zones or traffic_zone in rule_zones

    def _address_match(self, ip, rule_addresses):
        for addr in rule_addresses:
            if addr == 'any':
                return True
            if addr in self.parser.address_objects:
                cidr = self.parser.address_objects[addr]['value']
                if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                    return True
        return False

    def _service_match(self, services, protocol, port):
        for srv in services:
            if srv == 'any':
                return True
            if srv in self.parser.service_objects:
                service = self.parser.service_objects[srv]
                if service['protocol'] in [protocol, 'any']:
                    if service['port'] in [str(port), 'any']:
                        return True
        return False

if __name__ == "__main__":
    # User input
    firewall_host = input("Enter firewall IP/hostname: ")
    username = input("Username (press enter to skip): ") or None
    password = None  # Will prompt if needed
    
    try:
        # Collect configuration
        collector = PaloAltoConfigCollector(
            host=firewall_host,
            username=username,
            vsys='vsys1',
            verify_ssl=False
        )
        config_data = collector.get_full_config()
        
        # Parse configuration
        parser = PaloAltoConfigParser(config_data)
        
        # Initialize analyzer
        analyzer = TrafficAnalyzer(parser)
        
        # Get traffic parameters
        print("\nEnter traffic parameters:")
        src_ip = input("Source IP: ").strip()
        dst_ip = input("Destination IP: ").strip()
        protocol = input("Protocol (tcp/udp): ").strip().lower()
        port = input("Port: ").strip()
        
        # Analyze traffic
        result = analyzer.analyze_traffic(src_ip, dst_ip, protocol, port)
        
        # Display results
        if result:
            print(f"\nTraffic allowed by rule: {result['name']}")
            print(f"Action: {result['action'].upper()}")
            print(f"From Zones: {', '.join(result['from_zones'])}")
            print(f"To Zones: {', '.join(result['to_zones'])}")
        else:
            print("\nTraffic denied by firewall policy")

    except Exception as e:
        print(f"\nError: {str(e)}")
