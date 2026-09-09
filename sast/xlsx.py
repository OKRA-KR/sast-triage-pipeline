"""최소 XLSX 작성기 — stdlib(zipfile+xml)만. 외부 의존 0(폐쇄망 이식성 유지).

openpyxl 등을 반입 못 하는 폐쇄망에서도 다중 시트 엑셀을 낸다. 셀은 inlineStr 로 실어
sharedStrings 없이 자립. sheets = [(sheet_name, [header..], [[cell,..],..]), ..].
셀값: int/float=숫자, bool=Y/N, 그 외=문자열.
"""
import re, zipfile
from xml.sax.saxutils import escape

_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def _colref(ci):
    """0-기반 열 인덱스 → 'A','B',..,'Z','AA'."""
    s, n = "", ci + 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _cell(ci, ri, val):
    ref = f"{_colref(ci)}{ri}"
    if isinstance(val, bool):
        val = "Y" if val else "N"
    elif isinstance(val, (int, float)):
        return f'<c r="{ref}"><v>{val}</v></c>'
    s = escape("" if val is None else str(val))
    return f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{s}</t></is></c>'


def _sheet_xml(header, rows):
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           f'<worksheet xmlns="{_NS}"><sheetData>']
    ri = 1
    out.append(f'<row r="{ri}">' + "".join(_cell(ci, ri, h) for ci, h in enumerate(header)) + "</row>")
    for row in rows:
        ri += 1
        out.append(f'<row r="{ri}">' + "".join(_cell(ci, ri, v) for ci, v in enumerate(row)) + "</row>")
    out.append("</sheetData></worksheet>")
    return "".join(out)


def _safe_sheet(name, used):
    nm = re.sub(r'[\[\]:*?/\\]', "_", str(name))[:31] or "Sheet"
    base, i = nm, 2
    while nm.lower() in used:                 # 중복 시트명 회피
        nm = f"{base[:28]}_{i}"; i += 1
    used.add(nm.lower())
    return nm


def write(path, sheets):
    """sheets 를 xlsx 로 기록. sheets=[(name, header, rows), ..]. 반환: path."""
    used = set()
    sheets = [(_safe_sheet(nm, used), h, r) for nm, h, r in sheets]
    n = len(sheets)
    ct = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
          '<Default Extension="xml" ContentType="application/xml"/>',
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>']
    for i in range(1, n + 1):
        ct.append(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    ct.append("</Types>")
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
    wb_sheets = "".join(f'<sheet name="{escape(nm)}" sheetId="{i}" r:id="rId{i}"/>'
                        for i, (nm, _h, _r) in enumerate(sheets, 1))
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          f'<workbook xmlns="{_NS}" xmlns:r="{_NS_R}"><sheets>{wb_sheets}</sheets></workbook>')
    wb_rels = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
               '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    for i in range(1, n + 1):
        wb_rels.append(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>')
    wb_rels.append("</Relationships>")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "".join(ct))
        z.writestr("_rels/.rels", rels)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", "".join(wb_rels))
        for i, (_nm, header, rows) in enumerate(sheets, 1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", _sheet_xml(header, rows))
    return path
