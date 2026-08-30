#!/usr/bin/env python3
"""
EncDec Studio Pro — Desktop WebView & App Launcher
Runs the local server and opens a native desktop window (pywebview, Chromium App Mode, or Browser).
"""

import os
import sys
import time
import shutil
import socket
import threading
import webbrowser
import subprocess
from pathlib import Path

# Ensure current directory is prioritized in sys.path
current_dir = str(Path(__file__).resolve().parent)
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from EncDec_WebView import main as launcher_main

if __name__ == "__main__":
    launcher_main()
