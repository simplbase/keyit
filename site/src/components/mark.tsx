/**
 * Keyit mark + wordmark.
 *
 * The mark is a direct vector trace (via potrace) of the reference
 * artwork — a key shape whose bit resolves into three signed branches,
 * each terminating in a device node, with a small transmit/signal arc off
 * the middle branch. Traced rather than hand-redrawn so the on-site mark
 * matches the reference pixel-for-pixel; the path data below is exactly
 * what potrace produced from the source image, only re-pointed to
 * `currentColor` so it inherits the surrounding text color in both
 * themes.
 *
 * Natural aspect ratio is ~1.837:1 (wide), not square — `Mark` sizes by
 * `height` and derives width from that ratio rather than forcing a 24x24
 * box, so the artwork isn't squashed.
 */
const VIEW_BOX = "0 0 895.331964 487.405330";
const ASPECT_RATIO = 895.331964 / 487.405330;

export function Mark({ className, height = 18 }: { className?: string; height?: number }) {
  return (
    <svg
      width={height * ASPECT_RATIO}
      height={height}
      viewBox={VIEW_BOX}
      aria-hidden="true"
      className={className}
    >
      <g
        transform="translate(-179.038951,897.672602) scale(0.100000,-0.100000)"
        fill="currentColor"
      >
        <path d="M9156 8965 c-179 -46 -343 -206 -387 -379 l-11 -46 -475 0 c-532 0 -507 3 -555 -74 -14 -22 -140 -228 -280 -456 -141 -228 -269 -437 -287 -465 l-32 -50 -2282 -5 -2282 -5 -62 -28 c-54 -26 -94 -63 -350 -326 -297 -306 -320 -336 -349 -444 -19 -72 -18 -230 2 -298 34 -113 58 -144 314 -403 136 -138 261 -267 278 -287 61 -71 204 -126 296 -115 107 14 139 38 305 229 84 96 162 178 174 181 11 3 32 0 46 -7 14 -7 92 -90 174 -186 169 -196 196 -216 302 -215 103 1 135 25 302 224 80 96 155 178 167 181 43 11 73 -14 211 -182 77 -94 153 -179 170 -189 18 -11 55 -24 83 -31 63 -13 143 7 192 47 17 15 92 100 167 190 182 221 158 222 363 -15 94 -109 171 -189 195 -203 l40 -23 772 -5 772 -5 232 -375 c128 -206 268 -435 313 -509 64 -107 87 -137 113 -147 26 -11 129 -14 502 -14 l470 0 15 -54 c9 -30 39 -89 67 -131 237 -354 749 -313 928 75 136 296 -37 661 -354 746 -127 35 -284 9 -409 -66 -107 -65 -222 -219 -242 -326 l-6 -34 -437 0 -436 0 -310 502 c-171 276 -322 510 -335 519 -23 17 -79 19 -810 24 l-785 6 -54 57 c-29 31 -100 112 -158 179 -125 146 -168 173 -273 173 -53 0 -78 -6 -121 -27 -56 -29 -89 -65 -261 -280 -60 -75 -88 -103 -104 -103 -17 0 -51 34 -130 131 -164 201 -208 245 -261 263 -87 30 -185 18 -249 -30 -17 -13 -96 -100 -174 -194 -106 -126 -149 -170 -165 -170 -26 0 -52 28 -214 222 -141 169 -163 183 -296 183 -117 0 -132 -9 -269 -166 -59 -68 -132 -150 -161 -183 l-53 -59 -54 5 -53 5 -282 289 c-244 250 -286 296 -303 342 -24 63 -26 139 -4 211 14 49 38 76 291 337 220 227 282 286 311 294 25 6 804 10 2317 10 2201 0 2281 1 2310 19 21 12 75 90 174 252 143 233 192 313 364 589 49 80 96 155 104 168 l13 22 433 0 433 0 17 -57 c25 -80 76 -160 144 -224 110 -105 224 -152 368 -152 364 1 618 366 499 720 -22 66 -35 89 -89 161 -53 70 -153 142 -242 174 -76 27 -217 33 -297 13z" />
        <path d="M10254 7640 c-33 -13 -54 -50 -54 -95 0 -32 9 -54 43 -100 203 -281 319 -655 304 -980 -15 -311 -107 -564 -316 -864 -48 -69 -38 -136 26 -166 31 -15 40 -15 72 -3 73 27 252 332 330 563 69 205 84 301 85 525 0 174 -3 208 -27 321 -51 240 -146 467 -286 682 -81 123 -112 144 -177 117z" />
        <path d="M9073 7066 c-177 -43 -332 -187 -384 -357 l-21 -69 -1044 0 c-1135 0 -1086 2 -1112 -55 -23 -50 -5 -122 35 -141 10 -5 493 -11 1073 -14 l1054 -5 8 -39 c14 -66 70 -158 138 -227 211 -213 536 -218 744 -12 108 106 155 212 163 363 9 168 -40 294 -163 416 -133 133 -310 183 -491 140z" />
      </g>
    </svg>
  );
}

/** Mark + wordmark, used in the nav. Text stays plain — no typographic tricks yet. */
export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2.5 ${className ?? ""}`}>
      <Mark height={17} />
      <span className="font-mono text-sm font-medium tracking-tight">keyit</span>
    </span>
  );
}
