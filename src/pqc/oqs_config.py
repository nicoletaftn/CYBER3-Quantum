import os
import sys

# Add Homebrew liboqs path for M3 Macs
LIBOQS_PATH = "/opt/homebrew/opt/liboqs/lib"

if os.path.exists(LIBOQS_PATH):
    if LIBOQS_PATH not in os.environ.get('DYLD_LIBRARY_PATH', ''):
        os.environ['DYLD_LIBRARY_PATH'] = f"{LIBOQS_PATH}:{os.environ.get('DYLD_LIBRARY_PATH', '')}"