from PIL import Image, ImageDraw, ImageFont
import os

W, H = 1200, 627
C1 = (0, 161, 241)
C2 = (0, 136, 204)
WHITE = (255, 255, 255)
SOFT = (224, 243, 252)
DARK = (6, 46, 78)

FONTS = {
    "bold": r"C:\Windows\Fonts\segoeuib.ttf",
    "reg": r"C:\Windows\Fonts\segoeui.ttf",
    "light": r"C:\Windows\Fonts\segoeuil.ttf",
}

def font(name, size):
    return ImageFont.truetype(FONTS[name], size)

def rrect(d, box, r, fill, outline=None, width=1):
    d.rounded_rectangle(box, radius=r, fill=fill, outline=outline, width=width)

def vgrad(d):
    for y in range(H):
        t = y / H
        r = int(C1[0] + (C2[0] - C1[0]) * t)
        g = int(C1[1] + (C2[1] - C1[1]) * t)
        b = int(C1[2] + (C2[2] - C1[2]) * t)
        d.line([(0, y), (W, y)], fill=(r, g, b))

def draw_shield(d, cx, cy, s, fill):
    d.polygon([
        (cx, cy - s), (cx + s, cy - s // 2), (cx + s, cy + s // 3),
        (cx, cy + s), (cx - s, cy + s // 3), (cx - s, cy - s // 2),
    ], fill=fill)

img = Image.new("RGB", (W, H), WHITE)
d = ImageDraw.Draw(img)
vgrad(d)

overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
od = ImageDraw.Draw(overlay)
od.ellipse([-220, -220, 240, 240], fill=(255, 255, 255, 26))
img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")
d = ImageDraw.Draw(img)

f_small = font("reg", 22)
label = "EMAIL THREAT ANALYSIS"
tw = d.textlength(label, font=f_small)
rrect(d, [60, 62, 60 + tw + 36, 100], 20, DARK)
d.text((78, 68), label, font=f_small, fill=SOFT)

f_title = font("bold", 112)
d.text((58, 108), "PhishProbe", font=f_title, fill=WHITE)

f_tag = font("light", 40)
d.text((62, 226), "Phishing Email Analyzer for SOC Analysts", font=f_tag, fill=WHITE)

feats = [
    "Header + Full Email (.eml) Analysis",
    "SPF / DKIM / DMARC / ARC Authentication",
    "IOC Collection - URLs, Domains, IPs, Hashes",
    "Attachment Hash Checks (MD5 / SHA-1 / SHA-256)",
    "Typosquatting & Content Red-Flag Detection",
    "Instant, Explainable Verdict + Confidence %",
]
f_feat = font("reg", 26)
y = 300
for f in feats:
    d.line([(78, y + 13), (102, y + 13)], fill=SOFT, width=4)
    d.text((118, y - 8), f, font=f_feat, fill=WHITE)
    y += 48

bx = 700
f_metric = font("bold", 58)
f_metric_lbl = font("bold", 26)
f_metric_sm = font("reg", 20)

def metric(y0, label, value, sub, accent):
    rrect(d, [bx, y0, 1140, y0 + 118], 18, WHITE)
    d.rectangle([bx, y0, bx + 12, y0 + 118], fill=accent)
    d.text((bx + 34, y0 + 16), label, font=f_metric_lbl, fill=accent)
    d.text((bx + 34, y0 + 44), value, font=f_metric, fill=DARK)
    d.text((bx + 34, y0 + 106), sub, font=f_metric_sm, fill=(64, 96, 128))

RED = (220, 38, 38)
AMBER = (217, 119, 6)
GREEN = (22, 163, 74)

metric(300, "MTTD", "~30 sec", "Mean Time To Detect", RED)
metric(432, "MTTR", "~15 min", "Mean Time To Respond", GREEN)

f_pill = font("bold", 26)
def pill(x0, y0, text, color):
    pw = d.textlength(text, font=f_pill) + 44
    rrect(d, [x0, y0, x0 + pw, y0 + 50], 25, color)
    d.text((x0 + 22, y0 + 10), text, font=f_pill, fill=WHITE)
    return x0 + pw + 12

px = bx
for label, color in (("MALICIOUS", RED), ("SUSPICIOUS", AMBER), ("SAFE", GREEN)):
    px = pill(px, 566, label, color)

f_url = font("bold", 30)
f_url_sm = font("reg", 22)
rrect(d, [60, H - 74, W - 60, H - 18], 16, DARK)
d.text((82, H - 66), "phishprobe.onrender.com", font=f_url, fill=SOFT)
r2 = d.textlength("phishprobe.onrender.com", font=f_url) + 100
d.text((82 + r2, H - 60), "Try it live - No signup needed", font=f_url_sm, fill=WHITE)

draw_shield(d, 1180, 155, 34, SOFT)
d.text((1170, 142), "P", font=font("bold", 42), fill=C2)

out = r"C:\Users\MY LAP\Downloads\phishprobe\marketing\phishprobe-linkedin-banner.png"
os.makedirs(os.path.dirname(out), exist_ok=True)
img.save(out, "PNG")
print("Saved:", out)
