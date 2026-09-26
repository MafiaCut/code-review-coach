"""Launcher that avoids the debug reloader (causes exit on Python 3.14)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import app
app.run(debug=False, port=5000, use_reloader=False)
