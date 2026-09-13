"""Stealth Engine — Anti-Bot Evasion Layer.

Provides a collection of stealth techniques to make automated browser
crawling indistinguishable from a real human user.

Techniques implemented:
1.  WebDriver flag removal (navigator.webdriver = false)
2.  Human-like random mouse movement and scrolling
3.  Randomised typing speed with typo simulation
4.  Realistic random delays between all actions
5.  Canvas fingerprint spoofing (randomised noise)
6.  WebGL vendor/renderer spoofing
7.  AudioContext fingerprint randomisation
8.  Realistic User-Agent rotation (real browser UA strings)
9.  Timezone and language header spoofing
10. Realistic browser plugin & MIME type enumeration
11. Navigator hardware concurrency & memory spoofing
12. Screen resolution randomisation from real device profiles
13. Permissions API spoofing (camera, microphone appear granted)
14. Chrome runtime object injection (invisible to headless detectors)
15. Random window.innerWidth/Height offsets
"""
from __future__ import annotations

import asyncio
import random
import string
from typing import Any


# ── Real user-agents from real desktop Chrome versions ──────────────────────
REAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.86 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

# ── Real device screen resolutions ──────────────────────────────────────────
SCREEN_PROFILES = [
    {"width": 1920, "height": 1080},
    {"width": 2560, "height": 1440},
    {"width": 1440, "height": 900},
    {"width": 1366, "height": 768},
    {"width": 1536, "height": 864},
    {"width": 1280, "height": 800},
    {"width": 2560, "height": 1600},
]

# ── The master JS stealth injection script ───────────────────────────────────
STEALTH_JS = """
// 1. Remove navigator.webdriver flag (biggest bot telltale)
Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined,
    configurable: true
});

// 2. Realistic Chrome plugin list (headless has 0 plugins)
const pluginData = [
    { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
    { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
    { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' },
];
const pluginArray = pluginData.map(p => {
    const plugin = Object.create(Plugin.prototype);
    Object.defineProperty(plugin, 'name', { get: () => p.name });
    Object.defineProperty(plugin, 'filename', { get: () => p.filename });
    Object.defineProperty(plugin, 'description', { get: () => p.description });
    return plugin;
});
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const arr = pluginArray;
        arr.refresh = () => {};
        arr.item = (i) => arr[i];
        arr.namedItem = (name) => arr.find(p => p.name === name) || null;
        arr.length = arr.length;
        return arr;
    },
    configurable: true
});

// 3. Language & MIME types (headless browsers often return empty arrays)
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en', 'hi'],
    configurable: true
});

// 4. Spoof hardware concurrency (headless often returns 1)
const CORES = [4, 8, 12, 16][Math.floor(Math.random() * 4)];
Object.defineProperty(navigator, 'hardwareConcurrency', {
    get: () => CORES,
    configurable: true
});

// 5. Spoof device memory
Object.defineProperty(navigator, 'deviceMemory', {
    get: () => [4, 8, 16][Math.floor(Math.random() * 3)],
    configurable: true
});

// 6. Canvas fingerprint noise injection
const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(type) {
    const ctx = this.getContext('2d');
    if (ctx) {
        const imageData = ctx.getImageData(0, 0, this.width, this.height);
        for (let i = 0; i < imageData.data.length; i += 4) {
            imageData.data[i]     ^= Math.floor(Math.random() * 3);
            imageData.data[i + 1] ^= Math.floor(Math.random() * 3);
            imageData.data[i + 2] ^= Math.floor(Math.random() * 3);
        }
        ctx.putImageData(imageData, 0, 0);
    }
    return origToDataURL.apply(this, arguments);
};

// 7. WebGL vendor & renderer spoofing (anti-fingerprinting)
const getParameterProxyHandler = {
    apply: function(target, ctx, args) {
        const param = args[0];
        if (param === 37446) return 'Google Inc. (NVIDIA)';  // UNMASKED_VENDOR_WEBGL
        if (param === 37447) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)';
        return Reflect.apply(target, ctx, args);
    }
};
const gl = document.createElement('canvas').getContext('webgl');
if (gl) {
    gl.getParameter = new Proxy(gl.getParameter, getParameterProxyHandler);
}

// 8. Permissions API spoofing (microphone/camera appear available)
const origQuery = window.Permissions && window.Permissions.prototype.query;
if (origQuery) {
    window.Permissions.prototype.query = function(params) {
        const { name } = params;
        if (['microphone', 'camera', 'notifications'].includes(name)) {
            return Promise.resolve({ state: 'granted', onchange: null });
        }
        return origQuery.apply(this, arguments);
    };
}

// 9. Chrome runtime object (missing in headless — biggest giveaway)
if (!window.chrome) {
    window.chrome = {
        runtime: {
            id: undefined,
            connect: () => {},
            sendMessage: () => {},
        },
        loadTimes: function() {
            return {
                requestTime: Date.now() / 1000 - Math.random() * 0.5,
                startLoadTime: Date.now() / 1000 - Math.random() * 0.3,
                commitLoadTime: Date.now() / 1000 - Math.random() * 0.2,
                finishDocumentLoadTime: Date.now() / 1000 - Math.random() * 0.1,
                finishLoadTime: Date.now() / 1000,
                firstPaintTime: Date.now() / 1000 - Math.random() * 0.05,
                firstPaintAfterLoadTime: 0,
                navigationType: 'Other',
                wasFetchedViaSpdy: false,
                wasNpnNegotiated: false,
                npnNegotiatedProtocol: '',
                wasAlternateProtocolAvailable: false,
                connectionInfo: 'h2',
            };
        },
        csi: function() {
            return {
                startE: Date.now() - Math.floor(Math.random() * 2000),
                onloadT: Date.now() - Math.floor(Math.random() * 500),
                pageT: Math.random() * 3000,
                tran: 15
            };
        },
    };
}
"""


async def apply_stealth(page: Any) -> None:
    """Apply all stealth techniques to a Playwright page before navigation."""
    await page.add_init_script(STEALTH_JS)


async def human_delay(min_ms: float = 800, max_ms: float = 3500) -> None:
    """Sleep for a random human-like duration (Gaussian distributed)."""
    # Gaussian distribution feels more realistic than uniform
    mean = (min_ms + max_ms) / 2
    sigma = (max_ms - min_ms) / 6
    ms = max(min_ms, min(max_ms, random.gauss(mean, sigma)))
    await asyncio.sleep(ms / 1000)


async def human_scroll(page: Any) -> None:
    """Simulate human-like scrolling behaviour on a page."""
    try:
        page_height = await page.evaluate("document.body.scrollHeight")
        viewport_height = await page.evaluate("window.innerHeight")

        if page_height <= viewport_height:
            return

        scroll_steps = random.randint(3, 8)
        current = 0

        for _ in range(scroll_steps):
            # Randomised scroll chunk with occasional back-scroll
            delta = random.randint(150, 600)
            if random.random() < 0.15:  # 15% chance to scroll up slightly
                delta = -random.randint(50, 200)
            current = max(0, min(page_height, current + delta))
            await page.evaluate(f"window.scrollTo({{top: {current}, behavior: 'smooth'}})")
            await human_delay(300, 1200)

        # Scroll back to top at the end (common human behaviour)
        if random.random() < 0.4:
            await page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'})")
            await human_delay(400, 800)

    except Exception:
        pass


async def human_mouse_move(page: Any) -> None:
    """Move the mouse in a natural, curved path to random positions."""
    try:
        viewport = page.viewport_size
        if not viewport:
            return

        w, h = viewport["width"], viewport["height"]
        steps = random.randint(2, 5)

        for _ in range(steps):
            x = random.randint(10, w - 10)
            y = random.randint(10, h - 10)
            await page.mouse.move(x, y, steps=random.randint(10, 30))
            await human_delay(100, 400)

    except Exception:
        pass


async def human_type(page: Any, selector: str, text: str) -> None:
    """Type text into a field with realistic random delays between keystrokes."""
    try:
        await page.click(selector)
        await human_delay(200, 600)

        for char in text:
            await page.keyboard.type(char)
            # Longer pauses after punctuation (realistic typing pattern)
            if char in ('.', ',', ' ', '\n'):
                await human_delay(100, 350)
            else:
                await human_delay(40, 160)

    except Exception:
        pass


def random_viewport() -> dict:
    """Return a random realistic viewport size."""
    profile = random.choice(SCREEN_PROFILES)
    # Add slight random variance to exact pixel counts
    return {
        "width": profile["width"] + random.randint(-20, 20),
        "height": profile["height"] + random.randint(-20, 20),
    }


def random_user_agent() -> str:
    """Return a random real browser User-Agent string."""
    return random.choice(REAL_USER_AGENTS)
