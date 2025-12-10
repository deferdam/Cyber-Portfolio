# filename: DOCS_HOW_TO_RUN_SIMPLE.md
# content below is pure Markdown

# How to Run the Documentation (Simple)

This guide shows the easiest way to start and stop the documentation website.

---

## 1. Install what is needed

Open a terminal in the project folder and run:

python -m pip install -r requirements.txt

This installs MkDocs and all required tools.

---

## 2. Start the documentation

In the same folder (where mkdocs.yml is), run:

mkdocs serve

You will see a line like:

Serving on http://127.0.0.1:8000/

Open your browser and go to:

http://127.0.0.1:8000/

The documentation website will appear.

---

## 3. Stop the documentation

Go back to the terminal and press:

CTRL + C

The documentation server will stop.

---

## Quick command summary

Install dependencies:
python -m pip install -r requirements.txt

Start docs:
mkdocs serve

Stop docs:
CTRL + C

End of file.
