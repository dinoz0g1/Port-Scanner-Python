# Configuration for different scan types
SCAN_CONFIGS = {
    'quick': {'ports': [21,22,23,25,53,80,110,443,993,995], 'threads': 50},
    'full': {'ports': range(1, 1001), 'threads': 200},
    'web': {'ports': [80,443,8080,8443,3000,8000], 'threads': 100}
}