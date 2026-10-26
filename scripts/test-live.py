#!/usr/bin/env python3
"""Compatibility entrypoint for the capped lmaws-only live example harness."""
import os,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
args=[sys.executable,str(ROOT/'scripts/test-live-examples.py')]
if len(sys.argv)>1:args+=['--host',sys.argv[1]]
args+=['--write-only']
os.execv(sys.executable,args)
