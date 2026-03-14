#!/usr/bin/env python3
"""
Project Verification Script
WebSecure Analyzer - Ensures all files are present and configured correctly
Developed by: Kailas
"""

import sys
from pathlib import Path
import json


def check_files():
    """Verify all required files are present"""
    required_files = {
        'websecure_analyzer.py': 'Main scanner application',
        'utils.py': 'Helper utilities',
        'config.json': 'Configuration file',
        'requirements.txt': 'Python dependencies',
        'README.md': 'Main documentation',
        'USAGE_GUIDE.md': 'Usage instructions',
        'CHANGELOG.md': 'Version history',
        'LICENSE': 'License file',
        'PROJECT_SUMMARY.md': 'Project overview',
        'FILE_INDEX.md': 'File index',
        'interactive_security_lab.html': 'Educational lab',
        'quickstart.py': 'Quick start script',
        'batch_scanner.py': 'Batch scanner',
        '.gitignore': 'Git ignore rules'
    }
    
    print("="*60)
    print("WebSecure Analyzer - Project Verification")
    print("Developed by: Kailas")
    print("="*60)
    print("\nChecking project files...\n")
    
    missing = []
    present = []
    
    for filename, description in required_files.items():
        filepath = Path(filename)
        if filepath.exists():
            size = filepath.stat().st_size
            present.append((filename, description, size))
            print(f"✅ {filename:40s} ({size:>8,} bytes)")
        else:
            missing.append((filename, description))
            print(f"❌ {filename:40s} MISSING")
    
    print(f"\n{'='*60}")
    print(f"Files Present: {len(present)}/{len(required_files)}")
    print(f"{'='*60}\n")
    
    if missing:
        print("⚠️  Missing files:")
        for filename, desc in missing:
            print(f"  - {filename}: {desc}")
        return False
    
    return True


def check_dependencies():
    """Check if Python dependencies are installed"""
    print("\nChecking Python dependencies...\n")
    
    dependencies = ['aiohttp', 'bs4', 'lxml']
    missing = []
    
    for dep in dependencies:
        try:
            __import__(dep)
            print(f"✅ {dep}")
        except ImportError:
            print(f"❌ {dep} (not installed)")
            missing.append(dep)
    
    if missing:
        print("\n⚠️  Install missing dependencies:")
        print("   pip install -r requirements.txt")
        return False
    
    return True


def check_configuration():
    """Verify configuration file is valid"""
    print("\nChecking configuration...\n")
    
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        required_keys = ['scanner_settings', 'detection_patterns', 'reporting']
        
        for key in required_keys:
            if key in config:
                print(f"✅ Config section: {key}")
            else:
                print(f"❌ Missing config section: {key}")
                return False
        
        return True
    except Exception as e:
        print(f"❌ Error reading config: {e}")
        return False


def show_summary():
    """Show project summary"""
    print(f"\n{'='*60}")
    print("Project Summary")
    print(f"{'='*60}\n")
    
    print("📦 Project: WebSecure CSRF Vulnerability Analyzer")
    print("👨‍💻 Developer: Kailas")
    print("📅 Version: 2.0.0 (January 2026)")
    print("🔒 Purpose: Security Research & Education")
    
    print("\n📝 Quick Start:")
    print("   python quickstart.py")
    
    print("\n🚀 Run Scanner:")
    print("   python websecure_analyzer.py https://example.com")
    
    print("\n📚 Documentation:")
    print("   - README.md         : Main documentation")
    print("   - USAGE_GUIDE.md    : Detailed usage guide")
    print("   - PROJECT_SUMMARY.md: Complete overview")
    print("   - FILE_INDEX.md     : File directory")
    
    print("\n🎓 Educational:")
    print("   Open interactive_security_lab.html in browser")
    
    print(f"\n{'='*60}\n")


def main():
    """Main verification routine"""
    all_good = True
    
    # Check files
    if not check_files():
        all_good = False
    
    # Check dependencies
    if not check_dependencies():
        all_good = False
    
    # Check configuration
    if not check_configuration():
        all_good = False
    
    # Show summary
    show_summary()
    
    if all_good:
        print("✅ All checks passed! Project is ready to use.")
        print("\n💡 Next steps:")
        print("   1. Review README.md for overview")
        print("   2. Run: python quickstart.py")
        print("   3. Try educational lab: interactive_security_lab.html")
        return 0
    else:
        print("⚠️  Some checks failed. Please review errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
