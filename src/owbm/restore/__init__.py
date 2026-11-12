"""Restore: compatibility, planning, migration adaptation and (later) apply.

Everything here is a pure function of the archive manifest and the target
passport. No SSH, no subprocess, no file writes — that is what makes dry run
trustworthy rather than a flag.
"""
