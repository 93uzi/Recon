import subprocess
import argparse

def run_command(command):
    """Execute a command and print the output"""
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(result.stdout.decode())
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(e.stderr.decode())

def nmap_scan(ip):
    print(f"Running Nmap scan on {ip}...")
    command = f"nmap -p- --open -sS -T4 -sCV {ip}"
    run_command(command)

def feroxbuster_scan(domain):
    print(f"Running Feroxbuster scan on {domain}...")
    command = f"feroxbuster -u http://{domain}/ -t 50 --force-recursion"
    run_command(command)

def vhost_fuzzing(domain):
    print(f"Running Vhost fuzzing on {domain}...")
    command = f"ffuf -w /home/kali/Documents/BOX_HTB/SecLists/Discovery/DNS/namelist.txt -u http://{domain}/ -H 'HOST: FUZZ.{domain}'"
    run_command(command)

def subfinder_scan(domain):
    print(f"Running Subfinder scan on {domain}...")
    command = f"subfinder -d {domain}"
    run_command(command)

def nikto_scan(domain):
    print(f"Running Nikto scan on {domain}...")
    command = f"nikto -h http://{domain} -Tuning b"
    run_command(command)

def whatweb_scan(domain):
    print(f"Running WhatWeb scan on {domain}...")
    command = f"whatweb http://{domain}"
    run_command(command)

def wafw00f_scan(domain):
    print(f"Running Wafw00f scan on {domain}...")
    command = f"wafw00f http://{domain}"
    run_command(command)

def web_recon_well_known(domain):
    print(f"Checking .well-known on {domain}...")
    command = f"curl -s http://{domain}/.well-known/openid-configuration"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        json_data = result.stdout.decode()
        print("Received JSON:")
        print(json_data)
    else:
        print(f"Error retrieving .well-known information: {result.stderr.decode()}")

def main():
    parser = argparse.ArgumentParser(description="CTF Reconnaissance Tool")
    parser.add_argument("-i", "--ip", help="Target IP address", required=False)
    parser.add_argument("-u", "--url", help="Target domain URL", required=False)
    
    args = parser.parse_args()

    if args.ip:
        nmap_scan(args.ip)
    if args.url:
        feroxbuster_scan(args.url)
        vhost_fuzzing(args.url)
        subfinder_scan(args.url)
        nikto_scan(args.url)
        whatweb_scan(args.url)
        wafw00f_scan(args.url)
        web_recon_well_known(args.url)
    if not args.ip and not args.url:
        print("Please provide at least an IP address (-i) or a URL (-u).")

if __name__ == "__main__":
    main()
