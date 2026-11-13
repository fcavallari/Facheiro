"""Regenerates the Facheiro logo files: the cactus mark is plain geometry and
the wordmark is outlined from Alfa Slab One, so no font ships with the plugin.

    pip install fonttools uharfbuzz
    # drop Alfa Slab One Regular as build/logo/fonts/alfaslabone.ttf (OFL, from Google Fonts)
    python3 build/logo/make-logo.py && node build/logo/render.js

Writes assets/img/*.svg, .wordpress-org/icon.svg and the HTML sources for the PNGs."""
import os
import uharfbuzz as hb
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen

SP = os.path.dirname(os.path.abspath(__file__))          # build/logo
REPO = os.path.dirname(os.path.dirname(SP))
OUT = os.path.join(SP, "out")
FONT = os.path.join(SP, "fonts", "alfaslabone.ttf")   # Alfa Slab One Regular

# palette from site/index.html
BRANCO = "#eceee6"                    # the bleached ground of the caatinga
TINTA = "#14302d"                     # ink
GLAUCO, GLAUCO_CLARO, GLAUCO_TEXTO = "#4f8f88", "#b9d3cd", "#2b6a64"   # the cactus stem
BRASA, BRASA_CLARA = "#c2410c", "#e2551d"                              # ember
SOL = "#ecdca8"
CINZA = "#55605a"

def fmt(v):
    s = ("%.2f" % v).rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s

#### the mark: a facheiro (trunk and two arms) standing on a line of embers
def mark_markup(stem=GLAUCO_CLARO, ember=BRASA_CLARA, scale=1.0, weight=1.0):
    def n(v):
        return fmt((v - 50) * scale + 50)
    def w(v):
        return fmt(v * scale * weight)
    return "\n".join([
        '  <g fill="none" stroke="%s" stroke-linecap="round" stroke-linejoin="round">' % stem,
        '    <path d="M%s %sV%s" stroke-width="%s"/>' % (n(50), n(79), n(19), w(15)),
        '    <path d="M%s %sV%sQ%s %s %s %sH%s" stroke-width="%s"/>' % (n(25), n(40), n(57), n(25), n(66), n(34), n(66), n(50), w(11.5)),
        '    <path d="M%s %sV%sQ%s %s %s %sH%s" stroke-width="%s"/>' % (n(75), n(29), n(45), n(75), n(54), n(66), n(54), n(50), w(11.5)),
        '  </g>',
        '  <path d="M%s %sH%s" fill="none" stroke="%s" stroke-width="%s" stroke-linecap="round"/>' % (n(12), n(90), n(88), ember, w(5)),
    ])

#### the wordmark: "Facheiro" shaped with HarfBuzz (kerning) and outlined with fontTools
def wordmark(text="Facheiro", cap_height=46.0):
    tt = TTFont(FONT)
    cap = tt["OS/2"].sCapHeight
    s = cap_height / cap
    blob = hb.Blob.from_file_path(FONT)
    face = hb.Face(blob)
    font = hb.Font(face)
    buf = hb.Buffer()
    buf.add_str(text)
    buf.guess_segment_properties()
    hb.shape(font, buf, {"kern": True, "liga": True})
    glyph_order = tt.getGlyphOrder()
    gs = tt.getGlyphSet()
    pen = SVGPathPen(gs, ntos=fmt)
    x = 0.0
    xmin = ymin = 1e9; xmax = ymax = -1e9
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
        name = glyph_order[info.codepoint]
        # font units -> output units, flip y so the baseline is y=0 and glyphs rise upwards
        t = (s, 0, 0, -s, (x + pos.x_offset) * s, -pos.y_offset * s)
        gs[name].draw(TransformPen(pen, t))
        b = BoundsPen(gs); gs[name].draw(b)
        if b.bounds:
            bx0, by0, bx1, by1 = b.bounds
            xmin = min(xmin, (x + bx0) * s); xmax = max(xmax, (x + bx1) * s)
            ymin = min(ymin, -by1 * s); ymax = max(ymax, -by0 * s)
        x += pos.x_advance
    return pen.getCommands(), (xmin, ymin, xmax, ymax), x * s

def svg(w, h, body, extra_attrs=""):
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %s %s" width="%s" height="%s"%s>\n%s\n</svg>\n'
            % (fmt(w), fmt(h), fmt(w), fmt(h), extra_attrs, body))

def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
    print("wrote", path, len(content), "bytes")

title = "<title>Facheiro</title>\n"
# 1. the bare mark, transparent background (for dark surfaces)
write(os.path.join(REPO, "assets/img/facheiro-mark.svg"),
      svg(100, 100, title + mark_markup()))

# 2. the mark for light surfaces
write(os.path.join(REPO, "assets/img/facheiro-mark-on-light.svg"),
      svg(100, 100, title + mark_markup(stem=GLAUCO_TEXTO, ember=BRASA)))

# 3. the mark for the 20px admin menu: heavier lines, one colour (used as a mask)
menu = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="8 8 84 84" width="20" height="20">\n' + title
        + '  <!-- The Facheiro mark redrawn for the 20px admin menu: same shapes, heavier lines, one colour (used as a mask). -->\n'
        + mark_markup(stem="#000", ember="#000", weight=1.25) + '\n</svg>\n')
write(os.path.join(REPO, "assets/img/facheiro-menu.svg"), menu)

# 4. the lockup: mark + wordmark
d, (x0, y0, x1, y1), adv = wordmark()
gap = 10.0
text_x = 100 + gap - x0
cap_top = 50 - 46 / 2.0
baseline = cap_top + 46
width = text_x + x1 + 2
def lockup(stem, ember, ink):
    body = title + mark_markup(stem=stem, ember=ember)
    body += '\n  <path transform="translate(%s %s)" d="%s" fill="%s"/>' % (fmt(text_x), fmt(baseline), d, ink)
    return svg(width, 100, body, ' role="img" aria-label="Facheiro"')
write(os.path.join(REPO, "assets/img/facheiro-logo.svg"), lockup(GLAUCO_CLARO, BRASA_CLARA, BRANCO))
write(os.path.join(REPO, "assets/img/facheiro-logo-on-light.svg"), lockup(GLAUCO_TEXTO, BRASA, TINTA))

# 5. wordmark alone (dark surfaces), tight viewBox
wm_w = x1 - x0 + 2
def wordmark_svg(ink):
    body = '  <path transform="translate(%s %s)" d="%s" fill="%s"/>' % (fmt(1 - x0), fmt(-y0 + 1), d, ink)
    return svg(wm_w, y1 - y0 + 2, title + body, ' role="img" aria-label="Facheiro"')
write(os.path.join(REPO, "assets/img/facheiro-wordmark.svg"), wordmark_svg(BRANCO))

# 6. wordpress.org icon: ink square with the mark
icon_body = title + '  <rect width="100" height="100" fill="%s"/>\n' % TINTA + mark_markup(scale=0.86)
write(os.path.join(REPO, ".wordpress-org/icon.svg"), svg(100, 100, icon_body))

# 7. HTML pages for the PNG renders (banner + icons), rendered by Playwright
def page(w, h, bg, inner, css):
    return """<!doctype html><html><head><meta charset="utf-8"><style>
html,body{margin:0;background:%s}
body{width:%dpx;height:%dpx;overflow:hidden;position:relative;font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
%s
</style></head><body>%s</body></html>""" % (bg, w, h, css, inner)

mark_svg_light = svg(100, 100, mark_markup(stem=GLAUCO, ember=BRASA))
for W, H, k in ((1544, 500, 2), (772, 250, 1)):
    css = """
.sun{position:absolute;right:%dpx;top:%dpx;width:%dpx;height:%dpx;border-radius:50%%;background:%s}
.mark{position:absolute;right:%dpx;top:%dpx;width:%dpx;height:%dpx}
.rule{position:absolute;left:0;right:0;bottom:0;height:%dpx;background:%s}
.text{position:absolute;left:%dpx;top:%dpx}
.mark svg{display:block;width:100%%;height:100%%}
.text svg{display:block;width:%dpx;height:auto}
.tag{margin:%dpx 0 0 %dpx;color:%s;font-size:%dpx;line-height:1.45;white-space:nowrap}
.tag b{color:%s;font-weight:600}
""" % (56 * k, 26 * k, 150 * k, 150 * k, SOL,
       92 * k, 38 * k, 190 * k, 190 * k,
       6 * k, TINTA,
       64 * k, 70 * k, 330 * k, 20 * k, 2 * k, CINZA, 15 * k, TINTA)
    wm = wordmark_svg(TINTA).replace(title, "")
    inner = ('<div class="sun"></div><div class="mark">%s</div><div class="text">%s<p class="tag">Varredura de malware e resposta a incidentes para WordPress.<br><b>Tira o que fere e deixa o que serve.</b></p></div><div class="rule"></div>'
             % (mark_svg_light, wm))
    write(os.path.join(OUT, "banner-%dx%d.html" % (W, H)), page(W, H, BRANCO, inner, css))

for S in (128, 256):
    inner = '<div style="position:absolute;inset:0">%s</div>' % svg(100, 100, mark_markup(scale=0.86)).replace('width="100" height="100"', 'width="%d" height="%d"' % (S, S))
    write(os.path.join(OUT, "icon-%dx%d.html" % (S, S)), page(S, S, TINTA, inner, ""))
print("wordmark bounds", x0, y0, x1, y1, "lockup width", width)
