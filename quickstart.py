#!/usr/bin/env python3
"""
Quick Start Script for WebSecure Analyzer
Developed by: Kailas
"""

import subprocess
import sys
import os

def check_requirements():
    """Check if required packages are installed"""
    try:
        import aiohttp
        import bs4
        print("✓ All dependencies installed")
        return True
    except ImportError:
        print("✗ Missing dependencies. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ Dependencies installed successfully")
        return True

def run_example_scan():
    """Run an example scan"""
    print("\n" + "="*60)
    print("WebSecure Analyzer - Quick Start")
    print("Developed by: Kailas")
    print("="*60)
    
    target = input("\nEnter target URL (or press Enter for help): ").strip()
    
    if not target:
        print("\n📚 Usage Examples:")
        print("  python websecure_analyzer.py https://example.com")
        print("  python websecure_analyzer.py https://example.com -v")
        print("  python websecure_analyzer.py https://example.com -o report.md -d 3 -m 100")
        print("\n📖 For detailed guide, see USAGE_GUIDE.md")
        return
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    print(f"\n🎯 Starting scan of: {target}")
    print("⚠️  Make sure you have authorization to scan this target!\n")
    
    confirm = input("Continue? (yes/no): ").strip().lower()
    
    if confirm in ['yes', 'y']:
        cmd = [sys.executable, "websecure_analyzer.py", target, "-v"]
        subprocess.run(cmd)
    else:
        print("Scan cancelled.")

if __name__ == "__main__":
    if check_requirements():
        run_example_scan()
