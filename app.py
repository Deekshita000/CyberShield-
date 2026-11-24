import streamlit as st

from cybersheid.data import init_db
from cybersheid.ui import run

st.set_page_config(page_title="CYBERSHEID | Security Console", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
init_db()
run()
