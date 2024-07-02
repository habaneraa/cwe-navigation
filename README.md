# CWE Navigation

This project offers a graph visualization of weaknesses in CWE (Common Weakness Enumeration) list. The relationships (links between CWE IDs) are based on the well-known "Research Concepts View":

> CWE VIEW: Research Concepts
>
> View ID: 1000
>
> Objective: This view is intended to facilitate research into weaknesses, including their inter-dependencies, and can be leveraged to systematically identify theoretical gaps within CWE. It is mainly organized according to abstractions of behaviors instead of how they can be detected, where they appear in code, or when they are introduced in the development life cycle. By design, this view is expected to include every weakness within CWE.

The official CWE provides simple graphical visualizations [here](https://cwe.mitre.org/data/pdf/1000_abstraction_colors.pdf), but they are in PDF format and hard to read. This project aims to provide a better alternative by creating an interactive webpage where you can easily visualize the CWE tree structure, helping them grasp the connections between different software vulnerabilities. Also, you can easily navigate between different CWEs on one webpage.

## Development

We use a Python script (located at `data_script/cwe_catalog.py`) to deal with CWE data. It downloads and parses CWE content distribution at https://cwe.mitre.org/data/downloads.html and then generates data files that can be used by the front-end easily.

The webpage is developed using Vue3 and Echarts, built by Vite.
