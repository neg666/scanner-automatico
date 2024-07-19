# python scanner.py --help
# python scanner.py example.com --speed stealth

import subprocess
import argparse
import os
import sys

def print_banner():
    banner = r"""
              _____
             /     \
            | () () |
             \  ^  /
              |||||
              |||||
     ___  ___   ___  ___   ___    __    __    
    / 6 ) / 6 ) / 6 )( 6 \ / 6 )  /  \  /  \   
   / __/ / __/ / __/ \__  \\__  \ \__  \ \__  \ 
  /_/   /_/   /_/     /  /  /  /   /  /   /  / 
        ___  __    __  _    _  __    __         
       / 6 )/  \  /  \|  \ |  )/  \  /  \      
      / __/| __ \/ __/|   \|  /| __ \/ __/     
     /_/   |  \__|  \  |  \  / |  \__|  \      
             AUTOMATIZACION DE ESCANEO
    """
    print(banner)

def install_package(package_name):
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', package_name], check=True)
    except subprocess.CalledProcessError:
        print(f"Failed to install {package_name}. Please install it manually.")
        sys.exit(1)

def check_dependencies():
    try:
        import sublist3r
    except ImportError:
        print("Sublist3r is not installed. Installing now...")
        install_package('sublist3r')
    
    if subprocess.run(["which", "nmap"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode != 0:
        print("Nmap is not installed. Installing now...")
        if os.name == 'nt':
            print("Please install Nmap manually from https://nmap.org/download.html")
            sys.exit(1)
        else:
            subprocess.run(['sudo', 'apt-get', 'install', 'nmap', '-y'], check=True)

def run_sublist3r(domain):
    cmd = f"sublist3r -d {domain} -o subdomains.txt"
    subprocess.run(cmd, shell=True)
    with open('subdomains.txt', 'r') as file:
        subdomains = [line.strip() for line in file.readlines()]
    return subdomains

def run_nmap(target, speed, verbose):
    speed_options = {
        "stealth": "-T1",
        "normal": "-T3",
        "fast": "-T5"
    }
    if verbose:
        print(f"Scanning ports and services on {target} with speed {speed}...")
    cmd = f"nmap {speed_options[speed]} -sV -p- {target} -oN nmap_{target}.txt"
    subprocess.run(cmd, shell=True)
    with open(f'nmap_{target}.txt', 'r') as file:
        nmap_results = file.read()
    return nmap_results

def check_vulnerabilities(target, verbose):
    if verbose:
        print(f"Checking vulnerabilities on {target}...")
    cmd = f"nmap --script vuln {target} -oN vuln_{target}.txt"
    subprocess.run(cmd, shell=True)
    with open(f'vuln_{target}.txt', 'r') as file:
        vuln_results = file.read()
    return vuln_results

def scan_subdomains(domain):
    subdomains = run_sublist3r(domain)
    for subdomain in subdomains:
        print(f"Subdomain found: {subdomain}")
    return subdomains

def full_scan(domain, speed, verbose):
    subdomains = run_sublist3r(domain)
    for subdomain in subdomains:
        print(f"Scanning {subdomain}...")
        nmap_results = run_nmap(subdomain, speed, verbose)
        print(nmap_results)
        vuln_results = check_vulnerabilities(subdomain, verbose)
        print(vuln_results)
    print("Full scan completed.")
    return subdomains

def scan_without_subdomains(domain, speed, verbose):
    print(f"Scanning {domain}...")
    nmap_results = run_nmap(domain, speed, verbose)
    print(nmap_results)
    vuln_results = check_vulnerabilities(domain, verbose)
    print(vuln_results)
    print("Scan without subdomains completed.")

def main():
    print_banner()
    check_dependencies()
    
    parser = argparse.ArgumentParser(
        description='Automate subdomain, port, service, and vulnerability scanning. This script also checks for and installs necessary dependencies automatically.',
        epilog='Example usage: python scanner.py example.com --speed normal --verbose'
    )
    parser.add_argument('domain', type=str, help='The domain to scan.')
    parser.add_argument('--speed', type=str, choices=['stealth', 'normal', 'fast'], default='normal',
                        help='The speed of the scan. Options are: stealth (slow and stealthy), normal (balanced), fast (quick and loud).')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output.')
    args = parser.parse_args()

    while True:
        print("\nMenu:")
        print("1. Scan subdomains")
        print("2. Full scan (subdomains, ports, services, vulnerabilities)")
        print("3. Scan without subdomains (only ports, services, vulnerabilities)")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            subdomains = scan_subdomains(args.domain)
            print("\nSummary of subdomains found:")
            for subdomain in subdomains:
                print(subdomain)
        elif choice == '2':
            subdomains = full_scan(args.domain, args.speed, args.verbose)
            print("\nSummary of subdomains scanned:")
            for subdomain in subdomains:
                print(subdomain)
        elif choice == '3':
            scan_without_subdomains(args.domain, args.speed, args.verbose)
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
