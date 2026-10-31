#!/usr/bin/env python3
"""Original CC0 fixtures, reproduced with fonttools4.63.0 and brotli1.2.0.

Test-only generation: these tools are never runtime/build dependencies.
"""
from pathlib import Path
import hashlib
import struct
import zlib
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
ROOT=Path(__file__).resolve().parent.parent
PUBLIC=ROOT/'examples/public-articles/public'
PUBLIC.mkdir(exist_ok=True)
def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data))
width=height=8
pixels=b''.join(b'\0'+b''.join(bytes((25,105,175,255)) if (x+y)%2 else bytes((240,190,75,255)) for x in range(width)) for y in range(height))
png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,6,0,0,0))+chunk(b'IDAT',zlib.compress(pixels))+chunk(b'IEND',b'')
(PUBLIC/'tile.png').write_bytes(png)
font=FontBuilder(1000,isTTF=True)
font.setupGlyphOrder(['.notdef','space','A']);font.setupCharacterMap({32:'space',65:'A'})
glyphs={}
for name in ['.notdef','space','A']:
    pen=TTGlyphPen(None)
    if name!='space':
        pen.moveTo((100,0));pen.lineTo((350,700));pen.lineTo((600,0));pen.lineTo((475,0));pen.lineTo((350,400));pen.lineTo((225,0));pen.closePath()
    glyphs[name]=pen.glyph()
font.setupGlyf(glyphs);font.setupHorizontalMetrics({name:(700,0) for name in glyphs});font.setupHorizontalHeader(ascent=800,descent=-200)
font.setupNameTable({'familyName':'Noxide Proof','styleName':'Regular','uniqueFontIdentifier':'NoxideProof-CC0-1','fullName':'Noxide Proof Regular','psName':'NoxideProof-Regular','version':'Version 1.0'})
font.setupOS2(sTypoAscender=800,sTypoDescender=-200,usWinAscent=800,usWinDescent=200);font.setupPost();font.setupMaxp()
font.font['head'].created=font.font['head'].modified=2082844800;font.font.recalcTimestamp=False
font.font.flavor='woff2';font.save(PUBLIC/'proof.woff2')
font_digest=hashlib.sha256((PUBLIC/'proof.woff2').read_bytes()).hexdigest()
css="""@font-face { font-family: 'nxa-proof'; src: url('/_noxide/assets/FONT'); font-display: swap; }
p { color: rgb(12, 34, 56); font-family: 'nxa-proof', sans-serif; }
a { color: rgb(12, 34, 56); }
.card { display: grid; grid-template-columns: 1fr 2fr; gap: 1rem; padding: 1rem; border: 1px solid navy; }
@media (min-width: 30rem) { table { width: 100%; } }
@container panel (max-width: 20rem) { p { font-size: 1rem; } }
@keyframes nxa-fade { from { opacity: 0; } to { opacity: 1; } }
""".replace('FONT',font_digest)
(PUBLIC/'site.css').write_text(css)
print({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(PUBLIC.iterdir())})
