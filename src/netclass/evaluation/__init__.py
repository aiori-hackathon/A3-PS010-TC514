"""Reproducible evaluation of the existing PS-010 pipeline.

Nothing here classifies. The runner drives ``netclass.service.ClassificationService`` and
scores its answers. Importing this package imports nothing heavy; ``dataset``, ``metrics`` and
``report`` need only the standard library, ``replay`` and ``runner`` need the project's
dependencies (pydantic, requests).
"""
