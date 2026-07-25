"""
Synthetic architecture diagram generator with automatic YOLO annotations.
Generates diverse diagrams resembling AWS, Azure and generic software architectures.
v2: Added AWS/Azure icon-style rendering and evaluation-matching templates.
"""

import os
import math
import random
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import numpy as np

COMPONENT_CLASSES = [
    "user",            # 0
    "web_server",      # 1
    "database",        # 2
    "api_gateway",     # 3
    "load_balancer",   # 4
    "cache",           # 5
    "firewall",        # 6
    "cdn",             # 7
    "message_queue",   # 8
    "cloud_service",   # 9
    "mobile_app",      # 10
    "external_service" # 11
]

CLASS_TO_IDX = {c: i for i, c in enumerate(COMPONENT_CLASSES)}

# (border_color, bg_color) — generic style
COMPONENT_COLORS = {
    "user":             ("#4A90D9", "#D6E8F7"),
    "web_server":       ("#27AE60", "#D5F0DD"),
    "database":         ("#E8902A", "#FAE4C8"),
    "api_gateway":      ("#9B59B6", "#E8D5F5"),
    "load_balancer":    ("#1ABC9C", "#C8F0EA"),
    "cache":            ("#E74C3C", "#FAD5D2"),
    "firewall":         ("#922B21", "#F5C6C4"),
    "cdn":              ("#2980B9", "#C8E0F4"),
    "message_queue":    ("#F39C12", "#FDE9C3"),
    "cloud_service":    ("#8E44AD", "#E5D0F0"),
    "mobile_app":       ("#2C3E50", "#C8CDD4"),
    "external_service": ("#7F8C8D", "#DDE1E1"),
}

# AWS color scheme per component (icon_bg, symbol_color)
AWS_COLORS = {
    "user":             ("#4A90D9", "#FFFFFF"),
    "web_server":       ("#FF9900", "#FFFFFF"),
    "database":         ("#FF9900", "#FFFFFF"),
    "api_gateway":      ("#A855F7", "#FFFFFF"),
    "load_balancer":    ("#8C4FFF", "#FFFFFF"),
    "cache":            ("#C7131F", "#FFFFFF"),
    "firewall":         ("#DD344C", "#FFFFFF"),
    "cdn":              ("#8C4FFF", "#FFFFFF"),
    "message_queue":    ("#FF9900", "#FFFFFF"),
    "cloud_service":    ("#FF9900", "#FFFFFF"),
    "mobile_app":       ("#1A73E8", "#FFFFFF"),
    "external_service": ("#7F8C8D", "#FFFFFF"),
}

# Azure color scheme
AZURE_COLORS = {
    "user":             ("#0078D4", "#FFFFFF"),
    "web_server":       ("#0078D4", "#FFFFFF"),
    "database":         ("#0078D4", "#FFFFFF"),
    "api_gateway":      ("#0078D4", "#FFFFFF"),
    "load_balancer":    ("#0078D4", "#FFFFFF"),
    "cache":            ("#E81123", "#FFFFFF"),
    "firewall":         ("#E81123", "#FFFFFF"),
    "cdn":              ("#0078D4", "#FFFFFF"),
    "message_queue":    ("#0078D4", "#FFFFFF"),
    "cloud_service":    ("#0078D4", "#FFFFFF"),
    "mobile_app":       ("#00B4D8", "#FFFFFF"),
    "external_service": ("#7F8C8D", "#FFFFFF"),
}

COMPONENT_LABELS = {
    "user":             ["User", "Users", "Client", "Actor", "End User", "Browser", "Usuários"],
    "web_server":       ["Web Server", "App Server", "Application", "HTTP Server", "Service",
                         "Backend", "EC2", "App Service", "SEI/SIP", "Instance"],
    "database":         ["Database", "DB", "SQL DB", "PostgreSQL", "MySQL", "MongoDB",
                         "RDS", "Cosmos DB", "Aurora", "DynamoDB"],
    "api_gateway":      ["API Gateway", "API GW", "Gateway", "API Proxy", "API Management",
                         "APIM", "Kong"],
    "load_balancer":    ["Load Balancer", "LB", "ALB", "NLB", "Reverse Proxy", "Application LB"],
    "cache":            ["Cache", "Redis", "Memcached", "Cache Layer", "ElastiCache", "Azure Cache"],
    "firewall":         ["Firewall", "WAF", "Security Group", "NACL", "AWS Shield",
                         "Azure Firewall", "DDoS Protection"],
    "cdn":              ["CDN", "CloudFront", "Content Delivery", "Edge", "Akamai", "Azure CDN"],
    "message_queue":    ["Message Queue", "MQ", "SQS", "RabbitMQ", "Kafka",
                         "Event Bus", "Service Bus", "SNS"],
    "cloud_service":    ["Cloud Service", "Lambda", "Function", "Serverless", "Azure Func",
                         "Cloud Run", "CloudTrail", "CloudWatch", "KMS", "Logic Apps",
                         "Step Functions", "EventBridge", "Auto Scaling"],
    "mobile_app":       ["Mobile App", "iOS App", "Android App", "Mobile Client", "App", "Microsoft Entra"],
    "external_service": ["External API", "Third Party", "External Service", "Partner API",
                         "REST", "SOAP", "SaaS", "Web Service"],
}

# ── Architecture templates ────────────────────────────────────────────────────
TEMPLATES = {
    # ── Generic / training variety ─────────────────────────────────────────
    "three_tier_web": [
        ("user", 0, 1), ("firewall", 1, 1), ("load_balancer", 2, 1),
        ("web_server", 3, 0), ("web_server", 3, 1), ("web_server", 3, 2),
        ("database", 4, 0), ("cache", 4, 2),
    ],
    "microservices": [
        ("user", 0, 2), ("api_gateway", 1, 2),
        ("web_server", 2, 0), ("web_server", 2, 2), ("web_server", 2, 4),
        ("database", 3, 0), ("database", 3, 2),
        ("message_queue", 3, 3), ("cloud_service", 3, 4),
    ],
    "simple_saas": [
        ("user", 0, 1), ("load_balancer", 1, 1),
        ("web_server", 2, 0), ("web_server", 2, 2),
        ("database", 3, 1), ("cache", 3, 0),
    ],
    "mobile_backend": [
        ("mobile_app", 0, 0), ("user", 0, 2),
        ("api_gateway", 1, 1), ("firewall", 1, 0),
        ("web_server", 2, 0), ("web_server", 2, 2),
        ("database", 3, 0), ("cache", 3, 1), ("message_queue", 3, 2),
        ("external_service", 4, 1),
    ],
    "event_driven": [
        ("user", 0, 1), ("api_gateway", 1, 1), ("message_queue", 2, 1),
        ("cloud_service", 3, 0), ("cloud_service", 3, 2),
        ("database", 4, 0), ("database", 4, 2),
        ("external_service", 5, 1),
    ],
    "cdn_static": [
        ("user", 0, 1), ("cdn", 1, 0), ("firewall", 1, 2),
        ("load_balancer", 2, 1),
        ("web_server", 3, 0), ("web_server", 3, 2),
        ("database", 4, 1), ("cloud_service", 4, 0),
    ],

    # ── AWS-flavoured templates (match evaluation images) ──────────────────
    "aws_multi_az": [
        # top row: user → shield → cdn → waf
        ("user", 0, 0), ("firewall", 1, 0), ("cdn", 2, 0), ("firewall", 3, 0),
        # VPC: 3 AZ columns — ALB row
        ("load_balancer", 1, 1), ("load_balancer", 2, 1), ("load_balancer", 3, 1),
        # VPC: 3 AZ columns — app server row
        ("web_server", 1, 2), ("web_server", 2, 2), ("web_server", 3, 2),
        # bottom: storage tier
        ("database", 1, 3), ("database", 2, 3), ("cache", 3, 3),
        ("message_queue", 4, 3),
        # right: cloud services
        ("cloud_service", 5, 0), ("cloud_service", 5, 1),
        ("cloud_service", 5, 2), ("cloud_service", 5, 3),
    ],
    "aws_vpc": [
        ("user", 0, 1), ("cdn", 1, 1), ("firewall", 2, 1),
        ("load_balancer", 3, 1),
        ("web_server", 4, 0), ("web_server", 4, 1),
        ("database", 5, 0), ("cache", 5, 1),
        ("message_queue", 5, 2), ("cloud_service", 4, 2),
    ],
    "aws_serverless": [
        ("user", 0, 1), ("cdn", 1, 1), ("api_gateway", 2, 1),
        ("cloud_service", 3, 0), ("cloud_service", 3, 1), ("cloud_service", 3, 2),
        ("database", 4, 0), ("cache", 4, 1), ("message_queue", 4, 2),
        ("cloud_service", 5, 1),
    ],

    # ── Azure-flavoured templates ──────────────────────────────────────────
    "azure_api_management": [
        # left: clients
        ("mobile_app", 0, 0), ("user", 0, 2),
        # middle: API Management
        ("api_gateway", 1, 1),
        # orchestration
        ("cloud_service", 2, 0), ("web_server", 2, 1),
        # backend systems
        ("database", 3, 0), ("external_service", 3, 1), ("cache", 3, 2),
        ("cloud_service", 4, 0), ("external_service", 4, 2),
    ],
    "azure_full": [
        ("mobile_app", 0, 0), ("user", 0, 2),
        ("firewall", 1, 1),
        ("api_gateway", 2, 1),
        ("cloud_service", 3, 0), ("web_server", 3, 1), ("web_server", 3, 2),
        ("database", 4, 0), ("cache", 4, 1),
        ("message_queue", 4, 2), ("external_service", 5, 1),
    ],

    # ── Security-focused templates ─────────────────────────────────────────
    "zero_trust": [
        ("user", 0, 1), ("mobile_app", 0, 3),
        ("firewall", 1, 0), ("firewall", 1, 2), ("firewall", 1, 4),
        ("api_gateway", 2, 2),
        ("web_server", 3, 1), ("web_server", 3, 3),
        ("cloud_service", 4, 0), ("database", 4, 2), ("cache", 4, 4),
    ],
    "dmz_architecture": [
        ("user", 0, 1), ("external_service", 0, 3),
        ("firewall", 1, 2),  # outer firewall
        ("web_server", 2, 1), ("web_server", 2, 3),  # DMZ servers
        ("firewall", 3, 2),  # inner firewall
        ("api_gateway", 4, 1),
        ("database", 5, 0), ("web_server", 5, 2), ("cache", 5, 4),
    ],
}


def _hex_to_rgb(hex_color: str):
    h = hex_color.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def _draw_rounded_rect(draw, xy, radius, fill, outline, width=2):
    x0, y0, x1, y1 = xy
    draw.rectangle([x0+radius, y0, x1-radius, y1], fill=fill)
    draw.rectangle([x0, y0+radius, x1, y1-radius], fill=fill)
    for cx, cy in [(x0, y0), (x1-2*radius, y0), (x0, y1-2*radius), (x1-2*radius, y1-2*radius)]:
        draw.ellipse([cx, cy, cx+2*radius, cy+2*radius], fill=fill)
    draw.arc([x0, y0, x0+2*radius, y0+2*radius], 180, 270, fill=outline, width=width)
    draw.arc([x1-2*radius, y0, x1, y0+2*radius], 270, 360, fill=outline, width=width)
    draw.arc([x0, y1-2*radius, x0+2*radius, y1], 90, 180, fill=outline, width=width)
    draw.arc([x1-2*radius, y1-2*radius, x1, y1], 0, 90, fill=outline, width=width)
    draw.line([x0+radius, y0, x1-radius, y0], fill=outline, width=width)
    draw.line([x0+radius, y1, x1-radius, y1], fill=outline, width=width)
    draw.line([x0, y0+radius, x0, y1-radius], fill=outline, width=width)
    draw.line([x1, y0+radius, x1, y1-radius], fill=outline, width=width)


def _draw_cylinder(draw, xy, fill, outline):
    x0, y0, x1, y1 = xy
    ry = max(8, (y1-y0)//6)
    draw.rectangle([x0, y0+ry, x1, y1-ry], fill=fill)
    draw.ellipse([x0, y0, x1, y0+2*ry], fill=fill, outline=outline, width=2)
    draw.ellipse([x0, y1-2*ry, x1, y1], fill=fill, outline=outline, width=2)
    draw.line([x0, y0+ry, x0, y1-ry], fill=outline, width=2)
    draw.line([x1, y0+ry, x1, y1-ry], fill=outline, width=2)


def _draw_arrow(draw, start, end, color="#555555", label=None, font=None):
    draw.line([start, end], fill=color, width=2)
    dx, dy = end[0]-start[0], end[1]-start[1]
    length = max(1, (dx**2+dy**2)**0.5)
    udx, udy = dx/length, dy/length
    al, aa = 10, 0.4
    ax1 = end[0] - al*(udx*math.cos(aa) - udy*math.sin(aa))
    ay1 = end[1] - al*(udy*math.cos(aa) + udx*math.sin(aa))
    ax2 = end[0] - al*(udx*math.cos(-aa) - udy*math.sin(-aa))
    ay2 = end[1] - al*(udy*math.cos(-aa) + udx*math.sin(-aa))
    draw.polygon([end, (ax1, ay1), (ax2, ay2)], fill=color)
    if label and font:
        mx, my = (start[0]+end[0])//2, (start[1]+end[1])//2
        draw.text((mx+2, my-12), label, fill="#888888", font=font)


def _connection_point(x0, y0, x1, y1, direction):
    cx, cy = (x0+x1)//2, (y0+y1)//2
    return {
        "right": (x1, cy), "left": (x0, cy),
        "bottom": (cx, y1), "top": (cx, y0)
    }.get(direction, (cx, cy))


# ── Component drawing ─────────────────────────────────────────────────────────

def _draw_generic(draw, ctype, x0, y0, x1, y1, label, font):
    """Colored rectangle style (original)."""
    border_color, bg_color = COMPONENT_COLORS[ctype]
    bg = _hex_to_rgb(bg_color)
    border = _hex_to_rgb(border_color)
    if ctype == "database":
        _draw_cylinder(draw, (x0, y0, x1, y1), fill=bg, outline=border)
    elif ctype in ("firewall", "external_service"):
        draw.rectangle([x0, y0, x1, y1], fill=bg, outline=border, width=3)
    else:
        _draw_rounded_rect(draw, (x0, y0, x1, y1), radius=8, fill=bg, outline=border)
    short = label[:14]
    try:
        bb = draw.textbbox((0,0), short, font=font)
        tw, th = bb[2]-bb[0], bb[3]-bb[1]
    except Exception:
        tw, th = len(short)*7, 12
    draw.text(((x0+x1)//2 - tw//2, (y0+y1)//2 - th//2), short, fill=border, font=font)


def _draw_aws_icon(draw, ctype, x0, y0, x1, y1, label, font, font_small):
    """
    AWS-style: small colored square icon with label below.
    Matches the visual convention of AWS architecture diagrams.
    """
    icon_color, _ = AWS_COLORS[ctype]
    icon_rgb = _hex_to_rgb(icon_color)
    white = (255, 255, 255)

    cx = (x0+x1)//2
    # icon occupies ~70% of height, label below
    icon_h = int((y1-y0)*0.70)
    icon_w = min(icon_h, x1-x0)
    ix0 = cx - icon_w//2
    iy0 = y0
    ix1 = ix0 + icon_w
    iy1 = iy0 + icon_h

    if ctype == "database":
        _draw_cylinder(draw, (ix0, iy0, ix1, iy1), fill=icon_rgb, outline=(_hex_to_rgb("#333333")))
    elif ctype == "user":
        # Draw a person-like shape: circle head + body
        draw.ellipse([ix0+icon_w//3, iy0, ix0+2*icon_w//3, iy0+icon_h//2], fill=icon_rgb, outline=icon_rgb)
        draw.polygon([
            (cx, iy0+icon_h//2),
            (ix0+icon_w//6, iy1),
            (ix0+5*icon_w//6, iy1),
        ], fill=icon_rgb)
    elif ctype == "mobile_app":
        # Phone shape
        pw = icon_w//2
        draw.rounded_rectangle([cx-pw//2, iy0, cx+pw//2, iy1], radius=6, fill=icon_rgb)
        draw.ellipse([cx-3, iy1-10, cx+3, iy1-4], fill=white)
    else:
        # Generic AWS-style square icon
        _draw_rounded_rect(draw, (ix0, iy0, ix1, iy1), radius=10,
                           fill=icon_rgb, outline=(_hex_to_rgb("#333333")), width=1)
        # inner symbol (abbreviated text in white)
        sym = {
            "web_server": "EC2", "api_gateway": "GW", "load_balancer": "LB",
            "cache": "✕", "firewall": "⛨", "cdn": "⊕",
            "message_queue": "◫", "cloud_service": "λ",
            "external_service": "⇄",
        }.get(ctype, "")
        if sym:
            try:
                bb = draw.textbbox((0,0), sym, font=font)
                tw, th = bb[2]-bb[0], bb[3]-bb[1]
            except Exception:
                tw, th = 14, 12
            draw.text((cx - tw//2, (iy0+iy1)//2 - th//2), sym, fill=white, font=font)

    # label below icon
    short = label[:16]
    try:
        bb = draw.textbbox((0,0), short, font=font_small)
        tw = bb[2]-bb[0]
    except Exception:
        tw = len(short)*6
    draw.text((cx - tw//2, iy1+2), short, fill=_hex_to_rgb("#333333"), font=font_small)


def _draw_azure_icon(draw, ctype, x0, y0, x1, y1, label, font, font_small):
    """Azure-style: blue/white icon with label below."""
    icon_color, _ = AZURE_COLORS[ctype]
    icon_rgb = _hex_to_rgb(icon_color)
    white = (255, 255, 255)

    cx = (x0+x1)//2
    icon_h = int((y1-y0)*0.70)
    icon_w = min(icon_h, x1-x0)
    ix0 = cx - icon_w//2
    iy0 = y0
    ix1 = ix0 + icon_w
    iy1 = iy0 + icon_h

    if ctype == "database":
        _draw_cylinder(draw, (ix0, iy0, ix1, iy1), fill=icon_rgb, outline=(_hex_to_rgb("#005A9E")))
    else:
        # Azure uses circular/hex icons — use rounded square
        r = min(icon_w, icon_h) // 3
        _draw_rounded_rect(draw, (ix0, iy0, ix1, iy1), radius=r,
                           fill=icon_rgb, outline=(_hex_to_rgb("#005A9E")), width=1)
        sym = {
            "web_server": "App", "api_gateway": "APIM", "load_balancer": "LB",
            "cache": "Redis", "firewall": "FW", "cdn": "CDN",
            "message_queue": "Bus", "cloud_service": "Fx",
            "user": "👤", "mobile_app": "📱", "external_service": "API",
        }.get(ctype, "")
        if sym:
            try:
                bb = draw.textbbox((0,0), sym, font=font_small)
                tw, th = bb[2]-bb[0], bb[3]-bb[1]
            except Exception:
                tw, th = len(sym)*6, 10
            draw.text((cx-tw//2, (iy0+iy1)//2-th//2), sym, fill=white, font=font_small)

    short = label[:16]
    try:
        bb = draw.textbbox((0,0), short, font=font_small)
        tw = bb[2]-bb[0]
    except Exception:
        tw = len(short)*6
    draw.text((cx-tw//2, iy1+2), short, fill=_hex_to_rgb("#005A9E"), font=font_small)


class ArchitectureDiagramGenerator:
    IMG_W = 900
    IMG_H = 650
    COMP_W = 110
    COMP_H = 80

    VISUAL_STYLES = ["generic", "generic", "aws", "aws", "azure"]  # weighted

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self._load_font()

    def _load_font(self):
        candidates = [
            "/System/Library/Fonts/Helvetica.ttc",
            "/System/Library/Fonts/Arial.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        ]
        self.font = self.font_small = ImageFont.load_default()
        for path in candidates:
            if Path(path).exists():
                try:
                    self.font = ImageFont.truetype(path, 12)
                    self.font_small = ImageFont.truetype(path, 10)
                    break
                except Exception:
                    continue

    def generate_dataset(self, n_train=500, n_val=80, n_test=50):
        splits = [("train", n_train), ("val", n_val), ("test", n_test)]
        total = 0
        template_names = list(TEMPLATES.keys())
        for split, n in splits:
            img_dir = self.output_dir / "images" / split
            lbl_dir = self.output_dir / "labels" / split
            img_dir.mkdir(parents=True, exist_ok=True)
            lbl_dir.mkdir(parents=True, exist_ok=True)
            for i in range(n):
                tname = template_names[i % len(template_names)]
                style = random.choice(self.VISUAL_STYLES)
                img, annotations = self._generate_diagram(tname, style)
                fname = f"arch_{split}_{i:04d}"
                img.save(img_dir / f"{fname}.png")
                self._save_annotation(lbl_dir / f"{fname}.txt", annotations)
                total += 1
        print(f"Dataset generated: {total} images in {self.output_dir}")

    def _generate_diagram(self, template_name=None, style=None):
        if template_name is None:
            template_name = random.choice(list(TEMPLATES.keys()))
        if style is None:
            style = random.choice(self.VISUAL_STYLES)

        # Background
        bg_palette = {
            "generic": ["#FFFFFF", "#F8F9FA", "#F0F4F8", "#FAFAFA"],
            "aws":     ["#FFFFFF", "#F8F9FA", "#FFFFFF", "#FEFEFE"],
            "azure":   ["#FFFFFF", "#F0F8FF", "#F5F9FF", "#FAFCFF"],
        }
        bg_color = _hex_to_rgb(random.choice(bg_palette.get(style, ["#FFFFFF"])))

        img = Image.new("RGB", (self.IMG_W, self.IMG_H), bg_color)
        draw = ImageDraw.Draw(img)

        # light grid
        if random.random() < 0.25:
            for gx in range(0, self.IMG_W, 50):
                draw.line([(gx, 0), (gx, self.IMG_H)], fill="#EEEEEE", width=1)
            for gy in range(0, self.IMG_H, 50):
                draw.line([(0, gy), (self.IMG_W, gy)], fill="#EEEEEE", width=1)

        template = TEMPLATES[template_name]
        cols = max(c for _, c, _ in template) + 1
        rows = max(r for _, _, r in template) + 1

        margin_x, margin_y = 60, 80
        usable_w = self.IMG_W - 2*margin_x
        usable_h = self.IMG_H - 2*margin_y
        cell_w = usable_w // max(cols, 1)
        cell_h = usable_h // max(rows, 1)

        # aws/azure: components slightly smaller (icon-style)
        scale = random.uniform(0.75, 1.0) if style in ("aws", "azure") else random.uniform(0.85, 1.0)
        comp_w = int(min(self.COMP_W, cell_w - 15) * scale)
        comp_h = int(min(self.COMP_H, cell_h - 15) * scale)

        jx = random.randint(-12, 12)
        jy = random.randint(-8, 8)

        # cloud boundary zone
        if random.random() < 0.6:
            zone_colors = {
                "aws":     "#FFF8F0",
                "azure":   "#F0F4FF",
                "generic": "#F0FAF4",
            }
            zc = _hex_to_rgb(zone_colors.get(style, "#F5F5F5"))
            zone_labels = {
                "aws":     ["AWS Cloud", "VPC", "Private Subnet", "Availability Zone"],
                "azure":   ["Azure Region", "Resource Group", "Virtual Network"],
                "generic": ["Cloud", "Private Zone", "Secure Zone", "Internal Network"],
            }
            z_label = random.choice(zone_labels.get(style, ["Zone"]))
            first_col = min(c for _, c, _ in template)
            inner_cols = [c for _, c, _ in template if c > first_col]
            if inner_cols:
                zx0 = margin_x + min(inner_cols)*cell_w - 15
                zy0 = margin_y - 25
                zx1 = self.IMG_W - margin_x + 10
                zy1 = self.IMG_H - margin_y + 25
                draw.rectangle([zx0, zy0, zx1, zy1], fill=zc, outline="#BBBBBB", width=1)
                draw.text((zx0+5, zy0+4), z_label, fill="#AAAAAA", font=self.font_small)

        # compute bounding boxes
        boxes = []
        for ctype, col, row in template:
            cx = margin_x + col*cell_w + cell_w//2 + jx + random.randint(-6, 6)
            cy = margin_y + row*cell_h + cell_h//2 + jy + random.randint(-6, 6)
            x0 = max(5, cx - comp_w//2)
            y0 = max(5, cy - comp_h//2)
            x1 = min(self.IMG_W-5, x0 + comp_w)
            y1 = min(self.IMG_H-5, y0 + comp_h)
            boxes.append((ctype, x0, y0, x1, y1, col, row))

        # draw arrows
        arrow_colors = {
            "aws":     ["#555555", "#FF9900", "#146EB4"],
            "azure":   ["#555555", "#0078D4", "#00B4D8"],
            "generic": ["#555555", "#777777", "#3498DB", "#27AE60"],
        }
        edge_labels_pool = ["HTTPS", "HTTP", "TCP", "gRPC", "REST", "SQL", "AMQP", "TLS", "mTLS"]
        for i, (_, x0a, y0a, x1a, y1a, ca, ra) in enumerate(boxes):
            for j, (_, x0b, y0b, x1b, y1b, cb, rb) in enumerate(boxes):
                if i >= j:
                    continue
                if abs(ca-cb) <= 1 and abs(ra-rb) <= 1 and (abs(ca-cb)+abs(ra-rb)) > 0:
                    d_start = "right" if ca < cb else ("bottom" if ra < rb else "left")
                    d_end   = "left"  if ca < cb else ("top"    if ra < rb else "right")
                    s = _connection_point(x0a, y0a, x1a, y1a, d_start)
                    e = _connection_point(x0b, y0b, x1b, y1b, d_end)
                    ac = random.choice(arrow_colors.get(style, arrow_colors["generic"]))
                    el = random.choice(edge_labels_pool) if random.random() < 0.35 else None
                    _draw_arrow(draw, s, e, color=ac, label=el, font=self.font_small)

        # draw components
        annotations = []
        for ctype, x0, y0, x1, y1, col, row in boxes:
            label = random.choice(COMPONENT_LABELS[ctype])
            if style == "aws":
                _draw_aws_icon(draw, ctype, x0, y0, x1, y1, label, self.font, self.font_small)
            elif style == "azure":
                _draw_azure_icon(draw, ctype, x0, y0, x1, y1, label, self.font, self.font_small)
            else:
                _draw_generic(draw, ctype, x0, y0, x1, y1, label, self.font)

            cx_n = ((x0+x1)/2) / self.IMG_W
            cy_n = ((y0+y1)/2) / self.IMG_H
            w_n  = (x1-x0) / self.IMG_W
            h_n  = (y1-y0) / self.IMG_H
            annotations.append((CLASS_TO_IDX[ctype], cx_n, cy_n, w_n, h_n))

        return img, annotations

    def _save_annotation(self, path: Path, annotations):
        with open(path, "w") as f:
            for cls, cx, cy, w, h in annotations:
                f.write(f"{cls} {cx:.6f} {cy:.6f} {w:.6f} {h:.6f}\n")


# ── v2: 111 cloud-service classes (AWS + Azure + GCP) ─────────────────────────

COMPONENT_CLASSES_V2 = [
    "api", "aws_amazon_api_gateway", "aws_amazon_cloudfront", "aws_amazon_cloudwatch",
    "aws_amazon_dynamodb", "aws_amazon_ec2", "aws_amazon_ec2_auto_scaling",
    "aws_amazon_elastic_block_store", "aws_amazon_elastic_container_service",
    "aws_amazon_elastic_kubernetes_service", "aws_amazon_elasticache", "aws_amazon_rds",
    "aws_amazon_redshift", "aws_amazon_route_53", "aws_amazon_simple_notification_service",
    "aws_amazon_simple_queue_service", "aws_amazon_simple_storage_service",
    "aws_amazon_virtual_private_cloud", "aws_application_load_balancer",
    "aws_aurora_amazon_rds_instance", "aws_auto_scaling", "aws_autoscaling", "aws_backup",
    "aws_cloud", "aws_cloud_trail", "aws_cloudformation", "aws_cloudformation_template",
    "aws_cloudfront", "aws_cloudwatch", "aws_dynamodb_table", "aws_ec2_instance",
    "aws_ec2_instances", "aws_elactic_file_system(nfs)_multi-az",
    "aws_elastic_block_store_volume", "aws_elastic_container_service_container_2",
    "aws_elastic_container_service_service", "aws_elastic_load_balancing",
    "aws_elastic_load_balancing_application_load_balancer",
    "aws_elastic_load_balancing_network_load_balancer", "aws_elasticache",
    "aws_identity_access_management_role", "aws_identity_and_access_management",
    "aws_key_management_service", "aws_lambda", "aws_lambda_lambda_function",
    "aws_private_subnet", "aws_public_subnet", "aws_rds", "aws_region",
    "aws_route_53_hosted_zone", "aws_simple_email_service",
    "aws_simple_notification_service_topic", "aws_simple_queue_service_queue",
    "aws_simple_storage_service_bucket", "aws_simple_storage_service_bucket_with_objects",
    "aws_simple_storage_service_object", "aws_simple_storage_service_s3_standard",
    "aws_virtual_private_cloud", "aws_vpc_virtual_private_cloud_vpc", "aws_waf",
    "azure_api_management_services", "azure_app_services", "azure_application_insights",
    "azure_container_instances", "azure_cosmos_db", "azure_data_factories",
    "azure_databricks", "azure_devops", "azure_event_hubs", "azure_firewalls",
    "azure_function_apps", "azure_key_vaults", "azure_kubernetes_services",
    "azure_load_balancers", "azure_logic_apps", "azure_machine_learning",
    "azure_machine_learning_studio_workspaces", "azure_monitor",
    "azure_network_security_groups", "azure_openai", "azure_resource_groups",
    "azure_services", "azure_sql", "azure_sql_database", "azure_sql_managed_instance",
    "azure_sql_server", "azure_storage_accounts", "azure_synapse_analytics",
    "azure_virtual_machine", "azure_virtual_networks", "azure_vm_scale_sets",
    "developer_portal", "gcp_bigquery", "gcp_cloud_functions", "gcp_cloud_load_balancing",
    "gcp_cloud_run", "gcp_cloud_sql", "gcp_cloud_storage", "gcp_compute_engine",
    "gcp_google_kubernetes_engine", "gcp_identity_and_access_management", "gcp_pubsub",
    "gcp_vertex_ai", "gcp_virtual_private_cloud", "logic_apps", "microsoft_entra",
    "resource_group", "sass_services", "sei/sip", "solr", "user",
]

CLASS_TO_IDX_V2 = {c: i for i, c in enumerate(COMPONENT_CLASSES_V2)}


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "dataset"
    gen = ArchitectureDiagramGenerator(out)
    gen.generate_dataset(n_train=500, n_val=80, n_test=50)
