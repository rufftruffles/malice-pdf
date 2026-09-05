#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.
#
# Modernized (Python 3.12) Malice PDF Plugin analysis entry point.
# Invoked by the Go wrapper (scan.go):  python3 /app/pdfscan.py <file>
# Prints the result document (the exact plugins.document.pdf shape the classic
# engine wrote: {"pdfid": {...}, "streams": {...}, "markdown": "..."}) as a
# single JSON object.
#
# Analysis tools (Didier Stevens' original public-domain single-file tools, the
# same lineage the classic engine vendored):
#   * pdfid      0.2.10  -> /app/pdfid.py      (imported as a library)
#   * pdf-parser 0.7.14  -> /app/pdf-parser.py (invoked as a CLI)
#
# The engine is fully defensive: it always emits valid JSON. A non-PDF file
# yields a graceful result (matching the classic engine's
# "file cannot be analyzed by PDFiD because it is not a PDF") rather than
# crashing.

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile

from jinja2 import Template

try:
    import pdfid  # /app/pdfid.py (Didier Stevens' pdfid 0.2.10)
except Exception as _e:  # pragma: no cover - import guard
    pdfid = None
    _PDFID_IMPORT_ERROR = str(_e)
else:
    _PDFID_IMPORT_ERROR = None

log = logging.getLogger(__name__)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PDF_PARSER = os.path.join(APP_DIR, 'pdf-parser.py')
MARKDOWN_TEMPLATE = os.path.join(APP_DIR, 'markdown.jinja2')

# Triage keywords the classic engine carved/extracted (subset of the pdfid
# keyword set). "Colors > 2^24" is handled separately (its name is not a plain
# "/Name").
TRIAGE_KEYWORDS = ('JS', 'JavaScript', 'AA', 'OpenAction', 'AcroForm',
                   'JBIG2Decode', 'RichMedia', 'Launch', 'EmbeddedFile',
                   'XFA', 'Encrypt', 'Annot', 'URI')

# Classic-engine tuning (from the old MalPdfParser defaults / config.toml).
MAX_EXTRACT_COUNT = 5
MAX_CARVE_SIZE = 500


def sha256_checksum(filename, block_size=65536):
    h = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            h.update(block)
    return h.hexdigest()


def sha512_checksum(filename, block_size=65536):
    h = hashlib.sha512()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            h.update(block)
    return h.hexdigest()


def _sanitize(obj):
    """Recursively convert bytes keys/values to str so the result is JSON-safe.

    pdfid/pdf-parser can surface bytes; this is a safety net so the engine
    always emits valid JSON.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            nk = k.decode('utf-8', errors='replace') if isinstance(k, bytes) else k
            out[nk] = _sanitize(v)
        return out
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    if isinstance(obj, (list, tuple)):
        return [_sanitize(x) for x in obj]
    return obj


# ---------------------------------------------------------------------------
# pdfid (0.2.10)
# ---------------------------------------------------------------------------

def _keyword_map(pdfid_out):
    """Build {name: {'count': int, 'hexcodecount': int}} from the pdfid JSON."""
    kws = {}
    for kw in (pdfid_out.get('keywords') or {}).get('keyword') or []:
        kws[kw.get('name')] = {
            'count': int(kw.get('count', 0) or 0),
            'hexcodecount': int(kw.get('hexcodecount', 0) or 0),
        }
    return kws


def _cnt(kws, name):
    return kws.get(name, {'count': 0})['count']


def _heuristic_nameobfuscation(kws):
    if sum(v['hexcodecount'] for v in kws.values()) > 0:
        return dict(score=1000, reason='hex encoded flag(s) detected')
    return dict(score=0, reason='no hex encoded flag(s) detected')


def _heuristic_embeddedfile(kws):
    ef = kws.get('/EmbeddedFile')
    if ef and ef['count'] > 0:
        if ef['hexcodecount'] > 0:
            return dict(score=1000, reason='`/EmbeddedFile` flag(s) are hex encoded')
        return dict(score=50, reason='`/EmbeddedFile` flag(s) detected')
    return dict(score=0, reason='no `/EmbeddedFile` flag(s) detected')


def _heuristic_triage(kws):
    score = 0
    results = {'score': 0, 'reasons': []}
    reasons = {
        '/JS': '`/JS`: indicating javascript is present in the file.',
        '/JavaScript': '`/JavaScript`: indicating javascript is present in the file.',
        '/AA': '`/AA`: indicating automatic action to be performed when the page/document is viewed.',
        '/Annot': '`/Annot`: sample contains annotations.'
                  'Not suspicious but should be examined if other signs of maliciousness present.',
        '/OpenAction': '`/OpenAction`: indicating automatic action to be performed when the page/document is viewed.',
        '/AcroForm': '`/AcroForm`: sample contains AcroForm object. These can be used to hide malicious code.',
        '/JBIG2Decode': '`/JBIG2Decode`: indicating JBIG2 compression.',
        '/RichMedia': '`/RichMedia`: indicating embedded Flash.',
        '/Launch': '`/Launch`: counts launch actions.',
        '/Encrypt': '`/Encrypt`: encrypted content in sample',
        '/XFA': '`/XFA`: indicates XML Forms Architecture. These can be used to hide malicious code.',
        '/Colors > 2^24': '`/Colors > 2^24`: hits when the number of colors is expressed with more than 3 bytes.',
        '/ObjStm': '`/ObjStm`: sample contains object stream(s). Can be used to obfuscate objects.',
        '/URI': '`/URI`: sample contains URLs.',
    }
    # Javascript - separated so we do not double-score
    if _cnt(kws, '/JS') > 0:
        results['reasons'].append(reasons['/JS'])
    if _cnt(kws, '/JavaScript') > 0:
        results['reasons'].append(reasons['/JavaScript'])
    if _cnt(kws, '/JavaScript') > 0 or _cnt(kws, '/JS') > 0:
        score += 100
    for keyword in ('/JBIG2Decode', '/Colors > 2^24'):
        if _cnt(kws, keyword) > 0:
            results['reasons'].append(reasons[keyword])
            score += 50
    # Auto open/Launch - separated so we do not double-score
    if _cnt(kws, '/AA') > 0:
        results['reasons'].append(reasons['/AA'])
    if _cnt(kws, '/OpenAction') > 0:
        results['reasons'].append(reasons['/OpenAction'])
    if _cnt(kws, '/Launch') > 0:
        results['reasons'].append(reasons['/Launch'])
    if _cnt(kws, '/AA') > 0 or _cnt(kws, '/OpenAction') > 0 or _cnt(kws, '/Launch') > 0:
        score += 50
    # Forms, Flash, XFA
    for keyword in ('/AcroForm', '/RichMedia', '/XFA'):
        if _cnt(kws, keyword) > 0:
            results['reasons'].append(reasons[keyword])
            score += 25
    # Encrypted content
    for keyword in ['/Encrypt']:
        if _cnt(kws, keyword) > 0:
            results['reasons'].append(reasons[keyword])
            score += 25
    # Other content to flag for PDFParser to extract, but not to score
    for keyword in ['/Annot']:
        if _cnt(kws, keyword) > 0:
            results['reasons'].append(reasons[keyword])
            score += 1
    for keyword in ('/ObjStm',):
        if _cnt(kws, keyword) > 0:
            results['reasons'].append(reasons[keyword])
            score += 1
    for keyword in ['/URI']:
        if _cnt(kws, keyword) > 0:
            results['reasons'].append(reasons[keyword])
            score += 1
    results['score'] = score
    return results


def _heuristic_suspicious(kws, pdfid_out):
    score = 0
    results = {'score': 0, 'reasons': []}
    try:
        non_stream_entropy = float(pdfid_out.get('nonStreamEntropy') or 0)
    except (TypeError, ValueError):
        non_stream_entropy = 0.0
    try:
        last_eof_bytes = int(pdfid_out.get('countChatAfterLastEof') or 0)
    except (TypeError, ValueError):
        last_eof_bytes = 0
    # Entropy. Typically data outside of streams contain dictionaries & pdf
    # entities (mostly all ASCII text).
    if non_stream_entropy > 6:
        results['reasons'].append('Outside stream entropy of > 5')
        score += 500
    # Pages. Many malicious PDFs will contain only one page.
    if _cnt(kws, '/Page') == 1:
        results['reasons'].append('Page count of 1')
        score += 50
    # Characters after last %%EOF.
    if last_eof_bytes > 100:
        if last_eof_bytes > 499:
            results['reasons'].append('Over 500 characters after last %%EOF')
            score += 500
        else:
            results['reasons'].append('Over 100 characters after last %%EOF')
            score += 100
    if _cnt(kws, 'obj') != _cnt(kws, 'endobj'):
        results['reasons'].append('`obj` keyword count does not equal `endobj` keyword count')
        score += 50
    if _cnt(kws, 'stream') != _cnt(kws, 'endstream'):
        results['reasons'].append('`stream` keyword count does not equal `endstream` count')
        score += 50
    results['score'] = score
    return results


def run_pdfid(file_path):
    """Run pdfid 0.2.10 and return the plugins.document.pdf.pdfid sub-shape.

    For a non-PDF this returns the classic engine's error dict:
    {"error": "file cannot be analyzed by PDFiD because it is not a PDF"}.
    """
    if pdfid is None:
        return {'error': 'pdfid module not available: {}'.format(_PDFID_IMPORT_ERROR)}
    if not os.path.isfile(file_path):
        raise Exception("{} is not a valid file".format(file_path))

    # run the parser - returns an XML DOM instance
    pdf_data = pdfid.PDFiD(file_path, False, True)
    # convert to JSON. For a non-PDF there is no <Keywords> element, so
    # PDFiD2JSON raises IndexError (the classic engine handled it the same way).
    try:
        pdf_json = pdfid.PDFiD2JSON(pdf_data, True)
    except IndexError:
        if pdf_data.documentElement.getAttribute('IsPDF') != 'True':
            return {'error': 'file cannot be analyzed by PDFiD because it is not a PDF'}
        raise

    pdf_dict = json.loads(pdf_json)[0]
    pdfid_out = pdf_dict['pdfid']
    if pdfid_out.get('isPdf') != 'True':
        return {'error': 'file cannot be analyzed by PDFiD because it is not a PDF'}

    kws = _keyword_map(pdfid_out)
    # gather PDF heuristics (same logic as the classic MalPDFiD)
    pdfid_out['heuristics'] = {
        'nameobfuscation': _heuristic_nameobfuscation(kws),
        'embeddedfile': _heuristic_embeddedfile(kws),
        'triage': _heuristic_triage(kws),
        'suspicious': _heuristic_suspicious(kws, pdfid_out),
    }
    # clean up JSON (the classic engine dropped the filename)
    pdfid_out.pop('filename', None)
    return pdfid_out


# ---------------------------------------------------------------------------
# pdf-parser (0.7.14)
# ---------------------------------------------------------------------------

def _run_pdfparser(args, timeout=60):
    """Run pdf-parser.py with args; return (stdout, stderr, returncode)."""
    cmd = [sys.executable, PDF_PARSER] + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout, p.stderr, p.returncode
    except Exception as e:
        return '', str(e), 1


def _empty_streams():
    return {
        'stats': None,
        'embedded': [],
        'objstm': [],
        'tags': {},
        'carved': {'files': [], 'contents': []},
    }


def _pdfparser_stats(file_path):
    """Return the classic 'stats' list.

    pdf-parser 0.7.14 --stats prints the object statistics followed by a
    "Search keywords:" section; the classic shape is the object-statistics
    lines only (the modern "Indirect objects with a stream" line is dropped to
    match the classic output).
    """
    out, _, rc = _run_pdfparser(['--stats', file_path])
    if rc != 0 or not out.strip():
        return None
    stats = []
    for line in out.splitlines():
        if line.startswith('Search keywords:'):
            break
        if line.startswith('Indirect objects with a stream'):
            continue
        if line.strip():
            stats.append(line.strip())
    return stats if stats else None


def _object_blocks(text):
    """Split pdf-parser default output into (objnum, block_text) tuples."""
    blocks = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        m = re.match(r'^obj (\d+) \d+', lines[i])
        if m:
            objnum = m.group(1)
            block = [lines[i]]
            j = i + 1
            while j < n and not re.match(r'^obj \d+ \d+', lines[j]):
                block.append(lines[j])
                j += 1
            blocks.append((objnum, '\n'.join(block)))
            i = j
        else:
            i += 1
    return blocks


def _extract_embedded(file_path, dump_dir):
    """Extract /EmbeddedFile objects; return the classic 'embedded' list."""
    embedded = []
    out, _, rc = _run_pdfparser([file_path])
    if rc != 0 or not out.strip():
        return embedded
    # Collect object numbers whose type is /EmbeddedFile.
    obj_nums = []
    lines = out.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r'^obj (\d+) \d+', line)
        if m and i + 1 < len(lines) and 'Type: /EmbeddedFile' in lines[i + 1]:
            obj_nums.append(m.group(1))
    for obj in obj_nums[:MAX_EXTRACT_COUNT]:
        dump_name = "embedded_file_obj_{}".format(obj)
        dump_path = os.path.join(dump_dir, dump_name)
        _run_pdfparser(['--object', obj, '--filter', '--dump', dump_path, file_path])
        if os.path.exists(dump_path):
            embedded.append(dict(
                name=os.path.basename(dump_path),
                object=obj,
                sha256=sha256_checksum(dump_path),
                sha512=sha512_checksum(dump_path),
            ))
    return embedded


def _carve_content(file_path, kws):
    """Carve content for present triage keywords; return the classic 'carved'."""
    carved = {'files': [], 'contents': []}
    present = [kw for kw in TRIAGE_KEYWORDS if _cnt(kws, '/' + kw) > 0]
    if _cnt(kws, '/Colors > 2^24') > 0:
        present.append('Colors > 2^24')
    seen = set()
    for keyword in present:
        out, _, rc = _run_pdfparser(['--search', '/' + keyword, file_path])
        if rc != 0 or not out.strip():
            continue
        for _objnum, block in _object_blocks(out):
            # Carve the object dictionary (the << ... >> part) as the content.
            m = re.search(r'<<.*?>>', block, re.DOTALL)
            content = m.group(0).strip() if m else block.strip()
            if not content or content in seen:
                continue
            seen.add(content)
            if len(content) < MAX_CARVE_SIZE:
                carved['contents'].append(dict(key=keyword, content=content))
    return carved


def run_pdfparser(file_path, pdfid_out):
    """Run pdf-parser 0.7.14 and return the plugins.document.pdf.streams shape."""
    streams = _empty_streams()
    kws = _keyword_map(pdfid_out)
    dump_dir = tempfile.mkdtemp(prefix='pdfscan_')
    try:
        streams['stats'] = _pdfparser_stats(file_path)
        streams['embedded'] = _extract_embedded(file_path, dump_dir)
        streams['carved'] = _carve_content(file_path, kws)
        # 'objstm' and 'tags' are left as their empty defaults: the classic
        # engine populated them via ObjStm re-parsing and balbuzard IOC
        # matching, which are not reproduced here (see ledger).
    finally:
        shutil.rmtree(dump_dir, ignore_errors=True)
    return streams


# ---------------------------------------------------------------------------
# markdown
# ---------------------------------------------------------------------------

def render_markdown(results):
    with open(MARKDOWN_TEMPLATE) as f:
        return Template(f.read()).render(
            pdfid=results.get('pdfid'), streams=results.get('streams'))


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def analyze(file_path):
    results = {}

    # 1. pdfid (graceful on non-PDF)
    try:
        results['pdfid'] = run_pdfid(file_path)
    except Exception as e:
        log.exception("pdfid analysis failed")
        results['pdfid'] = {'error': str(e)}

    # 2. streams (graceful on non-PDF / error)
    pdfid_out = results.get('pdfid', {})
    if isinstance(pdfid_out, dict) and pdfid_out.get('isPdf') == 'True':
        try:
            results['streams'] = run_pdfparser(file_path, pdfid_out)
        except Exception as e:
            log.exception("pdf-parser analysis failed")
            results['streams'] = _empty_streams()
            results['streams']['error'] = str(e)
    else:
        results['streams'] = _empty_streams()

    # clean any bytes fields before rendering/storing
    results = _sanitize(results)

    # 3. markdown rendering (part of the stored document)
    try:
        results['markdown'] = render_markdown(results)
    except Exception as e:
        log.exception("failed to render markdown template")
        results['markdown'] = str(e)

    return results


def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if len(sys.argv) < 2:
        log.error("no file supplied")
        print(json.dumps({"error": "no file supplied"}))
        return 1

    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        log.error("file does not exist: %s", file_path)
        print(json.dumps({"error": "file does not exist: %s" % file_path}))
        return 1

    results = analyze(file_path)
    print(json.dumps(results))
    return 0


if __name__ == '__main__':
    sys.exit(main())
